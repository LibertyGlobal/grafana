import {coreModule} from 'app/core/core';

coreModule.directive('datasourceProxySettings', () => {
  return {
    scope: {
      current: '=',
    },
    templateUrl: 'public/app/features/datasources/partials/proxy_settings.html',
  };
});
