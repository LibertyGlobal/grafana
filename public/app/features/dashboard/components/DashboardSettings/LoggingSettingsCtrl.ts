import { coreModule } from 'app/core/core';

coreModule.directive('dashboardLoggingSettings', () => {
  return {
    scope: {
      current: '=',
    },
    templateUrl: 'public/app/features/dashboard/components/DashboardSettings/logging_settings.html',
  };
});
