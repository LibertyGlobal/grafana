import React from 'react';
import { HttpSettingsBaseProps } from './types';
import { Switch } from '../Forms/Legacy/Switch/Switch';

export const HttpProxySettings: React.FC<HttpSettingsBaseProps> = ({ dataSourceConfig, onChange }) => {
  return (
    <>
      <div className="gf-form-inline">
        <Switch
          label="TLS Client Auth"
          labelClass="width-13"
          checked={dataSourceConfig.jsonData.tlsAuth || false}
          onChange={(event) => onChange({ ...dataSourceConfig.jsonData, tlsAuth: event!.currentTarget.checked })}
        />

        <Switch
          label="With CA Cert"
          labelClass="width-13"
          checked={dataSourceConfig.jsonData.tlsAuthWithCACert || false}
          onChange={(event) =>
            onChange({ ...dataSourceConfig.jsonData, tlsAuthWithCACert: event!.currentTarget.checked })
          }
          tooltip="Needed for verifying self-signed TLS Certs"
        />
      </div>
      <div className="gf-form-inline">
        <Switch
          label="Skip TLS Verify"
          labelClass="width-13"
          checked={dataSourceConfig.jsonData.tlsSkipVerify || false}
          onChange={(event) => onChange({ ...dataSourceConfig.jsonData, tlsSkipVerify: event!.currentTarget.checked })}
        />
        <Switch
          label="Use HTTP Proxy"
          labelClass="width-13"
          checked={dataSourceConfig.jsonData.proxyEnabled || false}
          onChange={(event) => onChange({ ...dataSourceConfig.jsonData, proxyEnabled: event!.currentTarget.checked })}
          tooltip="Connect to the target of this datasource through the specified HTTP Proxy URL"
        />
      </div>
      <div className="gf-form-inline">
        <Switch
          label="Forward OAuth Identity"
          labelClass="width-13"
          checked={dataSourceConfig.jsonData.oauthPassThru || false}
          onChange={(event) => onChange({ ...dataSourceConfig.jsonData, oauthPassThru: event!.currentTarget.checked })}
          tooltip="Forward the user's upstream OAuth identity to the data source (Their access token gets passed along)."
        />
      </div>
    </>
  );
};
