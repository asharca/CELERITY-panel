/**
 * Reusable Clash subscription template model.
 */

const mongoose = require('mongoose');
const { validateTemplateSource } = require('../services/clashTemplateService');

const clashTemplateSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        maxlength: 80,
    },
    description: {
        type: String,
        default: '',
        trim: true,
        maxlength: 500,
    },
    yaml: {
        type: String,
        required: true,
        validate: {
            validator(value) {
                try {
                    validateTemplateSource(value);
                    return true;
                } catch (_) {
                    return false;
                }
            },
            message: 'yaml is not a valid Clash template',
        },
    },
    active: {
        type: Boolean,
        default: true,
        index: true,
    },
    revision: {
        type: Number,
        default: 1,
        min: 1,
        validate: {
            validator: Number.isInteger,
            message: 'revision must be an integer',
        },
    },
}, { timestamps: true });

// Store one canonical representation and enforce the exact same validation for
// model writes as for API previews/compilation. The route owns `$inc: revision`.
clashTemplateSchema.pre('validate', function normalizeYamlBeforeValidation() {
    if (!this.isModified('yaml') || typeof this.yaml !== 'string') return;
    try {
        this.yaml = validateTemplateSource(this.yaml).yaml;
    } catch (error) {
        this.invalidate('yaml', error.message, this.yaml, error.code || 'invalid');
    }
});

module.exports = mongoose.model('ClashTemplate', clashTemplateSchema);
