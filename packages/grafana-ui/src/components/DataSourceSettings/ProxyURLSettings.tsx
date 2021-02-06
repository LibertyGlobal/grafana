import React from 'react';
import { HttpSettingsProps } from './types';
import { FormField } from '../FormField/FormField';

export const ProxyURLSettings: React.FC<HttpSettingsProps> = ({ dataSourceConfig, onChange }) => {
  const onURLChange = (event: React.SyntheticEvent<HTMLInputElement>) => {
    onChange({
      ...dataSourceConfig,
      jsonData: {
        ...dataSourceConfig.jsonData,
        proxyURL: event.currentTarget.value,
      },
    });
  };

  return (
    <>
      <div className="gf-form">
        <FormField
          label="Proxy URL"
          labelWidth={10}
          inputWidth={18}
          placeholder="url"
          value={dataSourceConfig.jsonData.proxyURL || ''}
          onChange={onURLChange}
        />
      </div>
    </>
  );
};
