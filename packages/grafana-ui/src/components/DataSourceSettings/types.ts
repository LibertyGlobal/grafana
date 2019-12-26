import { DataSourceSettings } from '@grafana/data';

export interface HttpSettingsBaseProps {
  dataSourceConfig: DataSourceSettings<any, any>;
  onChange: (config: DataSourceSettings) => void;
}

export interface HttpSettingsProps extends HttpSettingsBaseProps {
  defaultUrl: string;
  showAccessOptions?: boolean;
}

export interface ProxySettingsProps extends HttpSettingsBaseProps {
  proxyURL?: string;
  proxyEnabled?: boolean;
}

export interface SecuritySettingsProps extends HttpSettingsBaseProps {
  loggingEnabled?: boolean;
  allowedTeams?: string;
  allowedAll?: boolean;
}
