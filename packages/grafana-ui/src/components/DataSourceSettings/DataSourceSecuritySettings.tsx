import React, { useCallback } from 'react';
import { SecuritySettingsProps } from './types';
import { DataSourceSettings } from '@grafana/data';
import { Switch } from '../Switch/Switch';
import { Input } from '../Input/Input';
import { FormField } from '../FormField/FormField';

export const DataSourceSecuritySettings: React.FC<SecuritySettingsProps> = ({ dataSourceConfig, onChange }) => {
  const onSettingsChange = useCallback(
    (change: Partial<DataSourceSettings<any, any>>) => {
      onChange({
        ...dataSourceConfig,
        ...change,
      });
    },
    [dataSourceConfig]
  );

  const textInput = (
    <Input
      className=""
      placeholder="List of teams"
      value={dataSourceConfig.jsonData.allowedTeams}
      onChange={event => {
        onSettingsChange({ jsonData: { ...dataSourceConfig.jsonData, allowedTeams: event!.currentTarget.value } });
      }}
    />
  );

  return (
    <div className="gf-form-group">
      <h3 className="page-heading">Security Enabled</h3>

      <Switch
        label="Audit enabled"
        labelClass="width-13"
        checked={dataSourceConfig.jsonData.loggingEnabled || false}
        onChange={event => {
          onSettingsChange({
            jsonData: { ...dataSourceConfig.jsonData, loggingEnabled: event!.currentTarget.checked },
          });
        }}
        tooltip="Audit records will be in logs"
      />

      <div className="gf-form">
        <FormField
          label="Allowed teams"
          labelWidth={11}
          tooltip="A comma-separated list of the user teams which are allowed to use this datasource.
    An empty list means that all users are allowed."
          inputEl={textInput}
        />
      </div>

      <Switch
        label="Allow all users"
        labelClass="width-13"
        checked={dataSourceConfig.jsonData.allowedAll || false}
        onChange={event => {
          onSettingsChange({ jsonData: { ...dataSourceConfig.jsonData, allowedAll: event!.currentTarget.checked } });
        }}
        tooltip="Allow all users"
      />
    </div>
  );
};
