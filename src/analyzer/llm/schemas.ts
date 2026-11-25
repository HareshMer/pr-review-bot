import { z } from 'zod';
import { Type, Schema } from '@google/genai';

export const ReviewFindingSchema = z.object({
  path: z.string().describe('Relative file path matching the diff'),
  line: z.number().int().positive().describe('The line number in the new file where the issue occurs'),
  severity: z.enum(['CRITICAL', 'WARNING', 'SUGGESTION']).describe('Severity level'),
  category: z.enum(['BUG', 'SECURITY', 'PERFORMANCE', 'CODE_QUALITY', 'BEST_PRACTICE']).describe('Category of finding'),
  title: z.string().max(100).describe('Concise title for the issue'),
  message: z.string().describe('Detailed explanation of why this is problematic and how to resolve it'),
  suggestion: z.string().optional().describe('Clean replacement code line(s) without markdown fences'),
  confidence: z
    .number()
    .min(0, 'Confidence must be at least 0.0')
    .max(1, 'Confidence cannot exceed 1.0')
    .describe('Mandatory confidence score between 0.0 and 1.0 (1.0 = absolute confidence)')
});

export const ReviewOutputSchema = z.object({
  summary: z.string().describe('High-level executive summary of the pull request changes in Markdown format'),
  findings: z.array(ReviewFindingSchema).describe('List of actionable review findings on specific changed lines')
});

export type ReviewFinding = z.infer<typeof ReviewFindingSchema>;
export type ReviewOutput = z.infer<typeof ReviewOutputSchema>;

/**
 * Compatible JSON schema for Google Gemini API's config.responseSchema (@google/genai v3.6.1)
 */
export const GEMINI_REVIEW_RESPONSE_SCHEMA: Schema = {
  type: Type.OBJECT,
  properties: {
    summary: {
      type: Type.STRING,
      description: 'High-level executive summary of the pull request changes in Markdown format'
    },
    findings: {
      type: Type.ARRAY,
      description: 'List of actionable review findings on specific changed lines',
      items: {
        type: Type.OBJECT,
        properties: {
          path: {
            type: Type.STRING,
            description: 'Relative file path matching the diff'
          },
          line: {
            type: Type.INTEGER,
            description: 'The line number in the new file where the issue occurs'
          },
          severity: {
            type: Type.STRING,
            enum: ['CRITICAL', 'WARNING', 'SUGGESTION'],
            description: 'Severity level'
          },
          category: {
            type: Type.STRING,
            enum: ['BUG', 'SECURITY', 'PERFORMANCE', 'CODE_QUALITY', 'BEST_PRACTICE'],
            description: 'Category of finding'
          },
          title: {
            type: Type.STRING,
            description: 'Concise title for the issue'
          },
          message: {
            type: Type.STRING,
            description: 'Detailed explanation of why this is problematic and how to resolve it'
          },
          suggestion: {
            type: Type.STRING,
            description: 'Clean replacement code line(s) without markdown fences'
          },
          confidence: {
            type: Type.NUMBER,
            description: 'Mandatory confidence score between 0.0 and 1.0'
          }
        },
        required: ['path', 'line', 'severity', 'category', 'title', 'message', 'confidence']
      }
    }
  },
  required: ['summary', 'findings']
};


