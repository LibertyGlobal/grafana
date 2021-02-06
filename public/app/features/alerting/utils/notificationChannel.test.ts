import { transformSubmitData } from './notificationChannels';
import { NotificationChannelDTO } from '../../../types';

const basicFormData: NotificationChannelDTO = {
  id: 1,
  uid: 'pX7fbbHGk',
  name: 'Pete discord',
  type: {
    value: 'discord',
    label: 'Discord',
    type: 'discord',
    name: 'Discord',
    heading: 'Discord settings',
    description: 'Sends notifications to Discord',
    info: '',
    options: [
      {
        element: 'input',
        inputType: 'text',
        label: 'Message Content',
        description: 'Mention a group using @ or a user using <@ID> when notifying in a channel',
        placeholder: '',
        propertyName: 'content',
        selectOptions: null,
        showWhen: { field: '', is: '' },
        required: false,
        validationRule: '',
        secure: false,
      },
      {
        element: 'input',
        inputType: 'text',
        label: 'Webhook URL',
        description: '',
        placeholder: 'Discord webhook URL',
        propertyName: 'url',
        selectOptions: null,
        showWhen: { field: '', is: '' },
        required: true,
        validationRule: '',
        secure: false,
      },
    ],
    typeName: 'discord',
  },
  isDefault: false,
  sendReminder: false,
  disableResolveMessage: false,
  frequency: '',
  created: '2020-08-24T10:46:43+02:00',
  updated: '2020-09-02T14:08:27+02:00',
  settings: {
    url: 'https://discordapp.com/api/webhooks/',
    uploadImage: true,
    content: '',
    autoResolve: true,
    httpMethod: 'POST',
    severity: 'critical',
  },
  secureFields: {},
  secureSettings: {},
  proxyEnabled: false,
  proxyURL: '',
};

const selectFormData: NotificationChannelDTO = {
  id: 23,
  uid: 'BxEN9rNGk',
  name: 'Webhook',
  type: {
    value: 'webhook',
    label: 'webhook',
    type: 'webhook',
    name: 'webhook',
    heading: 'Webhook settings',
    description: 'Sends HTTP POST request to a URL',
    info: '',
    options: [
      {
        element: 'input',
        inputType: 'text',
        label: 'Url',
        description: '',
        placeholder: '',
        propertyName: 'url',
        selectOptions: null,
        showWhen: { field: '', is: '' },
        required: true,
        validationRule: '',
        secure: false,
      },
      {
        element: 'select',
        inputType: '',
        label: 'Http Method',
        description: '',
        placeholder: '',
        propertyName: 'httpMethod',
        selectOptions: [
          { value: 'POST', label: 'POST' },
          { value: 'PUT', label: 'PUT' },
        ],
        showWhen: { field: '', is: '' },
        required: false,
        validationRule: '',
        secure: false,
      },
      {
        element: 'input',
        inputType: 'text',
        label: 'Username',
        description: '',
        placeholder: '',
        propertyName: 'username',
        selectOptions: null,
        showWhen: { field: '', is: '' },
        required: false,
        validationRule: '',
        secure: false,
      },
      {
        element: 'input',
        inputType: 'password',
        label: 'Password',
        description: '',
        placeholder: '',
        propertyName: 'password',
        selectOptions: null,
        showWhen: { field: '', is: '' },
        required: false,
        validationRule: '',
        secure: true,
      },
    ],
    typeName: 'webhook',
  },
  isDefault: false,
  sendReminder: false,
  disableResolveMessage: false,
  frequency: '',
  created: '2020-08-28T10:47:37+02:00',
  updated: '2020-09-03T09:37:21+02:00',
  settings: {
    autoResolve: true,
    httpMethod: 'POST',
    password: '',
    severity: 'critical',
    uploadImage: true,
    url: 'http://asdf',
    username: 'asdf',
  },
  secureFields: { password: true },
  secureSettings: {},
  proxyEnabled: false,
  proxyURL: '',
};

describe('Transform submit data', () => {
  it('basic transform', () => {
    const expected = {
      id: 1,
      name: 'Pete discord',
      type: 'discord',
      sendReminder: false,
      disableResolveMessage: false,
      frequency: '15m',
      settings: {
        uploadImage: true,
        autoResolve: true,
        httpMethod: 'POST',
        severity: 'critical',
        url: 'https://discordapp.com/api/webhooks/',
        content: '',
      },
      secureSettings: {},
      secureFields: {},
      isDefault: false,
      uid: 'pX7fbbHGk',
      created: '2020-08-24T10:46:43+02:00',
      updated: '2020-09-02T14:08:27+02:00',
    };

    expect(transformSubmitData(basicFormData)).toEqual(expected);
  });

  it('should transform form data with selects', () => {
    const expected = {
      created: '2020-08-28T10:47:37+02:00',
      disableResolveMessage: false,
      frequency: '15m',
      id: 23,
      isDefault: false,
      name: 'Webhook',
      secureFields: { password: true },
      secureSettings: {},
      sendReminder: false,
      settings: {
        autoResolve: true,
        httpMethod: 'POST',
        password: '',
        severity: 'critical',
        uploadImage: true,
        url: 'http://asdf',
        username: 'asdf',
      },
      type: 'webhook',
      uid: 'BxEN9rNGk',
      updated: '2020-09-03T09:37:21+02:00',
    };

    expect(transformSubmitData(selectFormData)).toEqual(expected);
  });
});
