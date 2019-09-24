import {coreModule} from 'app/core/core';

coreModule.directive('datasourceSecuritySettings', () => {
  return {
    scope: {
      current: '=',
    },
    templateUrl: 'public/app/features/datasources/partials/security_settings.html',
  };
});
