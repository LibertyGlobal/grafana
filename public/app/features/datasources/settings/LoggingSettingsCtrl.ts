import { coreModule } from 'app/core/core';

coreModule.directive('datasourceLoggingSettings', () => {
  return {
    scope: {
      current: '=',
    },
    templateUrl: 'public/app/features/datasources/partials/logging_settings.html',
  };
});
