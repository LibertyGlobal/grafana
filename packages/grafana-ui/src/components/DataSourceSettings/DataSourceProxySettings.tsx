import React, { useCallback } from 'react';
import { ProxySettingsProps } from './types';
import { DataSourceSettings } from '@grafana/data';
import { Switch } from '../Switch/Switch';
import { Input } from '../Input/Input';
import { FormField } from '../FormField/FormField';

export const DataSourceProxySettings: React.FC<ProxySettingsProps> = ({ dataSourceConfig, onChange }) => {
  const onSettingsChange = useCallback(
    (change: Partial<DataSourceSettings<any, any>>) => {
      onChange({
        ...dataSourceConfig,
        ...change,
      });
    },
    [dataSourceConfig]
  );

  const urlInput = (
    <Input
      className=""
      placeholder="http://127.0.0.1:3128"
      value={dataSourceConfig.jsonData.proxyURL}
      onChange={event => {
        onSettingsChange({ jsonData: { ...dataSourceConfig.jsonData, proxyURL: event!.currentTarget.value } });
      }}
    />
  );

  return (
    <div className="gf-form-group">
      <h3 className="page-heading">Proxy Settings</h3>

      <Switch
        label="Proxy enabled"
        labelClass="width-10"
        checked={dataSourceConfig.jsonData.proxyEnabled || false}
        onChange={event => {
          onSettingsChange({ jsonData: { ...dataSourceConfig.jsonData, proxyEnabled: event!.currentTarget.checked } });
        }}
        tooltip="Proxy enabled"
      />

      <div className="gf-form">
        <FormField label="Proxy URL" labelWidth={10} tooltip="Enter proxy URL" inputEl={urlInput} />
      </div>

    </div>
  );
};
