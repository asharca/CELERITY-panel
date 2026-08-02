const express = require('express');
const mongoose = require('mongoose');

const ClashTemplate = require('../../models/clashTemplateModel');
const HyUser = require('../../models/hyUserModel');
const {
    ClashTemplateError,
    normalizeTemplateInput,
    validateTemplateSource,
} = require('../../services/clashTemplateService');
const cache = require('../../services/cacheService');
const logger = require('../../utils/logger');
const { render } = require('./helpers');

const router = express.Router();

function validationMessage(result) {
    if (!result || result === true || result.valid !== false) return null;
    if (Array.isArray(result.errors) && result.errors.length > 0) {
        return result.errors.map((item) => item?.message || String(item)).join('; ');
    }
    return result.error || result.message || 'Invalid Clash template';
}

async function parseTemplateBody(body) {
    try {
        const normalized = normalizeTemplateInput({
            name: body.name,
            description: body.description,
            yaml: body.yaml,
            active: body.active === 'on',
        });
        const validation = await Promise.resolve(validateTemplateSource(normalized.yaml));
        const errorMessage = validationMessage(validation);
        if (errorMessage) throw new ClashTemplateError('TEMPLATE_INVALID', errorMessage);
        return {
            ...normalized,
            yaml: validation.yaml,
        };
    } catch (error) {
        if (error instanceof ClashTemplateError) error.statusCode = 400;
        throw error;
    }
}

async function findReferencedUsers(templateId) {
    return HyUser.find({ clashTemplate: templateId })
        .select('userId subscriptionToken')
        .lean();
}

async function invalidateUsers(users) {
    const batchSize = 50;
    for (let index = 0; index < users.length; index += batchSize) {
        const batch = users.slice(index, index + batchSize);
        await Promise.all(batch.map((user) => (
            user.subscriptionToken
                ? cache.invalidateSubscription(user.subscriptionToken)
                : Promise.resolve()
        )));
    }
}

async function loadPageData(editId = null, draft = null) {
    const [templates, usage] = await Promise.all([
        ClashTemplate.find().sort({ name: 1 }).lean(),
        HyUser.aggregate([
            { $match: { clashTemplate: { $ne: null } } },
            { $group: { _id: '$clashTemplate', count: { $sum: 1 } } },
        ]),
    ]);
    const usageById = new Map(usage.map((item) => [String(item._id), item.count]));
    const templatesWithUsage = templates.map((template) => ({
        ...template,
        usersCount: usageById.get(String(template._id)) || 0,
    }));

    let editingTemplate = draft;
    if (!editingTemplate && editId && mongoose.isValidObjectId(editId)) {
        editingTemplate = templatesWithUsage.find((template) => String(template._id) === String(editId)) || null;
    }

    return { templates: templatesWithUsage, editingTemplate };
}

function renderTemplatePage(res, data, { error = null, status = 200, notice = null } = {}) {
    return render(res.status(status), 'clash-templates', {
        title: res.locals.t('clashTemplates.title'),
        page: 'clashTemplates',
        error,
        notice,
        ...data,
    });
}

// GET /clash-templates - list templates and optionally open one for editing.
router.get('/clash-templates', async (req, res) => {
    try {
        const editId = String(req.query.edit || '');
        const data = await loadPageData(editId);
        if (editId && !data.editingTemplate) {
            return res.redirect('/panel/clash-templates');
        }
        const notices = new Set(['created', 'updated', 'deleted']);
        const notice = notices.has(String(req.query.notice)) ? String(req.query.notice) : null;
        return renderTemplatePage(res, data, { notice });
    } catch (error) {
        logger.error(`[Panel] Clash templates list error: ${error.message}`);
        return res.status(500).send(`${res.locals.t('common.error')}: ${error.message}`);
    }
});

// POST /clash-templates - create a template.
router.post('/clash-templates', async (req, res) => {
    try {
        const input = await parseTemplateBody(req.body);
        await ClashTemplate.create(input);
        return res.redirect('/panel/clash-templates?notice=created');
    } catch (error) {
        const duplicate = error.code === 11000;
        const status = error.statusCode || (duplicate ? 409 : 500);
        const draft = {
            name: String(req.body.name || ''),
            description: String(req.body.description || ''),
            yaml: String(req.body.yaml || ''),
            active: req.body.active === 'on',
        };
        const data = await loadPageData(null, draft);
        return renderTemplatePage(res, data, {
            error: duplicate ? res.locals.t('clashTemplates.duplicateName') : error.message,
            status,
        });
    }
});

// POST /clash-templates/:id - update a template and expire every affected subscription.
router.post('/clash-templates/:id', async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) return res.sendStatus(404);
        const input = await parseTemplateBody(req.body);
        const referencedUsers = await findReferencedUsers(req.params.id);
        const updated = await ClashTemplate.findByIdAndUpdate(
            req.params.id,
            { $set: input, $inc: { revision: 1 } },
            { runValidators: true, new: true }
        );
        if (!updated) return res.sendStatus(404);
        await invalidateUsers(referencedUsers);
        return res.redirect('/panel/clash-templates?notice=updated');
    } catch (error) {
        const duplicate = error.code === 11000;
        const status = error.statusCode || (duplicate ? 409 : 500);
        const draft = {
            _id: req.params.id,
            name: String(req.body.name || ''),
            description: String(req.body.description || ''),
            yaml: String(req.body.yaml || ''),
            active: req.body.active === 'on',
        };
        const data = await loadPageData(null, draft);
        return renderTemplatePage(res, data, {
            error: duplicate ? res.locals.t('clashTemplates.duplicateName') : error.message,
            status,
        });
    }
});

// POST /clash-templates/:id/delete - remove the template and fall affected users back to defaults.
router.post('/clash-templates/:id/delete', async (req, res) => {
    try {
        if (!mongoose.isValidObjectId(req.params.id)) return res.sendStatus(404);
        // Deactivate first so a concurrent user edit cannot create a new
        // reference between the unlink and delete operations.
        const template = await ClashTemplate.findByIdAndUpdate(
            req.params.id,
            { $set: { active: false } },
            { new: true }
        ).select('_id').lean();
        if (!template) return res.sendStatus(404);

        const referencedUsers = await findReferencedUsers(req.params.id);
        await HyUser.updateMany(
            { clashTemplate: req.params.id },
            { $unset: { clashTemplate: 1 } }
        );
        await ClashTemplate.findByIdAndDelete(req.params.id);
        await invalidateUsers(referencedUsers);
        return res.redirect('/panel/clash-templates?notice=deleted');
    } catch (error) {
        logger.error(`[Panel] Clash template delete error: ${error.message}`);
        return res.status(500).send(`${res.locals.t('common.error')}: ${error.message}`);
    }
});

module.exports = router;
