import { describe, it, expect } from 'vitest';
import { applyManifest, EVENT_BY_TAG, LATEST } from '../js/schema.js';

describe('sysmon -s schema', () => {
  it('updates fields, adds new events and targets the new schema', () => {
    const res = applyManifest(`System Monitor v15.99
<manifest schemaversion="4.99" binaryversion="15.99"><configuration><filters><filter>is</filter></filters></configuration><events>
  <event name="SYSMON_CREATE_PROCESS" value="1" template="Process Create" rulename="ProcessCreate"><data name="RuleName"/><data name="Image"/><data name="NewField"/></event>
  <event name="SYSMON_NEW" value="30" template="New thing" rulename="NewThing"><data name="RuleName"/><data name="Image"/></event>
</events></manifest>`, 'windows');
    expect(res).toMatchObject({ schemaversion: '4.99', added: ['NewThing'], changed: ['ProcessCreate'] });
    expect(EVENT_BY_TAG.ProcessCreate.fields).toContain('NewField');
    expect(EVENT_BY_TAG.NewThing.ids).toEqual([30]);
    expect(EVENT_BY_TAG.DnsQuery.platforms).not.toContain('windows');
    expect(LATEST.windows.schema).toBe('4.99');
  });

  it('rejects output without a manifest', () => {
    expect(() => applyManifest('nope', 'windows')).toThrow(/No <manifest>/);
  });
});
