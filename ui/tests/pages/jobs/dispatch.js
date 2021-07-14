import {
  clickable,
  collection,
  create,
  fillable,
  isPresent,
  property,
  text,
  visitable,
} from 'ember-cli-page-object';
import { codeFillable, code } from 'nomad-ui/tests/pages/helpers/codemirror';

export default create({
  visit: visitable('/jobs/:id/dispatch'),

  dispatchButton: {
    scope: '[data-test-dispatch-button]',
    isDisabled: property('disabled'),
    click: clickable(),
  },

  metaFields: collection('[data-test-meta-field]', {
    field: {
      scope: '[data-test-meta-field-input]',
      input: fillable(),
      id: property('id'),
    },
    label: text('[data-test-meta-field-label]'),
  }),

  payload: {
    editor: {
      scope: '[data-test-payload-editor]',
      isPresent: isPresent(),
      contents: code('[data-test-payload-editor]'),
      fillIn: codeFillable('[data-test-payload-editor]'),
    },
    emptyMessage: {
      scope: '[data-test-empty-payload-message]',
      isPresent: isPresent(),
    },
  },
});
