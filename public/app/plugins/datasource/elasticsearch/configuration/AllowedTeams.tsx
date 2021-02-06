import React from 'react';
import { LegacyForms } from '@grafana/ui';
const { Switch, FormField } = LegacyForms;
import { ElasticsearchOptions } from '../types';
import { DataSourceSettings } from '@grafana/data';

type Props = {
  value: DataSourceSettings<ElasticsearchOptions>;
  onChange: (value: DataSourceSettings<ElasticsearchOptions>) => void;
};

export const AllowedTeams = (props: Props) => {
  const { value, onChange } = props;

  const onTeamsListChange = (event: React.SyntheticEvent<HTMLInputElement>) => {
    onChange({
      ...value,
      jsonData: {
        ...value.jsonData,
        allowedTeams: event.currentTarget.value,
      },
    });
  };

  const onAllUsersChange = (event: React.SyntheticEvent<HTMLInputElement>) => {
    onChange({
      ...value,
      jsonData: {
        ...value.jsonData,
        allowedAll: event!.currentTarget.checked,
      },
    });
  };

  return (
    <>
      <h3 className="page-heading">Allowed Teams</h3>
      <div className="gf-form-group">
        <div className="gf-form-inline">
          <div className="gf-form max-width-25">
            <FormField
              label="Allowed Teams List"
              labelWidth={10}
              inputWidth={18}
              placeholder=""
              value={value.jsonData.allowedTeams || ''}
              onChange={onTeamsListChange}
            />
            <Switch
              label="Allow all users"
              labelClass="width-10"
              checked={value.jsonData.allowedAll || false}
              onChange={onAllUsersChange}
            />
          </div>
        </div>
      </div>
    </>
  );
};
