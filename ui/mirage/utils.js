import faker from 'nomad-ui/mirage/faker';

export function provide(count, provider) {
  if (typeof count === 'function') {
    count = count();
  }
  return Array(count).fill(null).map(provider);
}

export function provider() {
  return () => provide(...arguments);
}

export function pickOne(list) {
  return list[faker.random.number(list.length - 1)];
}

export function arrToObj(prop, alias = '') {
  return (obj, element) => {
    const name = element[prop];
    delete element[prop];

    obj[name] = alias ? element[alias] : element;
    return obj;
  };
}

export const generateAcceptanceTestEvalMock = (id) => {
  return {
    CreateIndex: 20,
    CreateTime: 1647899150314738000,
    ID: id,
    JobID: 'example',
    JobModifyIndex: 10,
    ModifyIndex: 31,
    ModifyTime: 1647899318007569000,
    Namespace: 'default',
    NextEval: 'fd1cd898-d655-c7e4-17f6-a1a2e98b18ef',
    PreviousEval: 'd8a5c14f-120a-3d83-6305-90927356dd6c',
    Priority: 50,
    RelatedEvals: [
      {
        BlockedEval: '',
        CreateIndex: 31,
        CreateTime: 1647899318007563000,
        DeploymentID: '',
        ID: 'fd1cd898-d655-c7e4-17f6-a1a2e98b18ef',
        JobID: 'example',
        ModifyIndex: 44,
        ModifyTime: 1647899591412413000,
        Namespace: 'default',
        NextEval: 'cac7dfa0-b79b-ee55-c86a-0ca89dffb9e1',
        NodeID: '',
        PreviousEval: id,
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 10,
        CreateTime: 1647899129298997000,
        DeploymentID: '',
        ID: 'd8a5c14f-120a-3d83-6305-90927356dd6c',
        JobID: 'example',
        ModifyIndex: 20,
        ModifyTime: 1647899150314745000,
        Namespace: 'default',
        NextEval: id,
        NodeID: '',
        PreviousEval: '',
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'job-register',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 44,
        CreateTime: 1647899591412410000,
        DeploymentID: '',
        ID: 'cac7dfa0-b79b-ee55-c86a-0ca89dffb9e1',
        JobID: 'example',
        ModifyIndex: 53,
        ModifyTime: 1647899729480596000,
        Namespace: 'default',
        NextEval: 'e49bf53c-da6a-c869-8317-f2089682f503',
        NodeID: '',
        PreviousEval: 'fd1cd898-d655-c7e4-17f6-a1a2e98b18ef',
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 53,
        CreateTime: 1647899729480592000,
        DeploymentID: '',
        ID: 'e49bf53c-da6a-c869-8317-f2089682f503',
        JobID: 'example',
        ModifyIndex: 64,
        ModifyTime: 1647899881302731000,
        Namespace: 'default',
        NextEval: 'a8d29cfc-517c-2e4c-9722-b47e84152c64',
        NodeID: '',
        PreviousEval: 'cac7dfa0-b79b-ee55-c86a-0ca89dffb9e1',
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 64,
        CreateTime: 1647899881302723000,
        DeploymentID: '',
        ID: 'a8d29cfc-517c-2e4c-9722-b47e84152c64',
        JobID: 'example',
        ModifyIndex: 81,
        ModifyTime: 1647900212725381000,
        Namespace: 'default',
        NextEval: 'b37d06e4-4eb4-b29d-3b4a-b0c7bf2528ad',
        NodeID: '',
        PreviousEval: 'e49bf53c-da6a-c869-8317-f2089682f503',
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 81,
        CreateTime: 1647900212725376000,
        DeploymentID: '',
        ID: 'b37d06e4-4eb4-b29d-3b4a-b0c7bf2528ad',
        JobID: 'example',
        ModifyIndex: 97,
        ModifyTime: 1647900516944239000,
        Namespace: 'default',
        NextEval: 'd7c50aa5-5bf1-5119-d7e7-0d0ae5381856',
        NodeID: '',
        PreviousEval: 'a8d29cfc-517c-2e4c-9722-b47e84152c64',
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 97,
        CreateTime: 1647900516944236000,
        DeploymentID: '',
        ID: 'd7c50aa5-5bf1-5119-d7e7-0d0ae5381856',
        JobID: 'example',
        ModifyIndex: 114,
        ModifyTime: 1647900825385587000,
        Namespace: 'default',
        NextEval: 'ea2239aa-26d6-8874-8c56-e1600585772b',
        NodeID: '',
        PreviousEval: 'b37d06e4-4eb4-b29d-3b4a-b0c7bf2528ad',
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 114,
        CreateTime: 1647900825385584000,
        DeploymentID: '',
        ID: 'ea2239aa-26d6-8874-8c56-e1600585772b',
        JobID: 'example',
        ModifyIndex: 128,
        ModifyTime: 1647900979511304000,
        Namespace: 'default',
        NextEval: '25a2dd19-8d22-d1dd-280a-79860c9b8bdb',
        NodeID: '',
        PreviousEval: 'd7c50aa5-5bf1-5119-d7e7-0d0ae5381856',
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 128,
        CreateTime: 1647900979511301000,
        DeploymentID: '',
        ID: '25a2dd19-8d22-d1dd-280a-79860c9b8bdb',
        JobID: 'example',
        ModifyIndex: 136,
        ModifyTime: 1647901211369652000,
        Namespace: 'default',
        NextEval: '1fded690-20ad-6afa-3b89-59e319dfce18',
        NodeID: '',
        PreviousEval: 'ea2239aa-26d6-8874-8c56-e1600585772b',
        Priority: 50,
        Status: 'failed',
        StatusDescription: 'evaluation reached delivery limit (3)',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
      {
        BlockedEval: '',
        CreateIndex: 136,
        CreateTime: 1647901211369648000,
        DeploymentID: '',
        ID: '1fded690-20ad-6afa-3b89-59e319dfce18',
        JobID: 'example',
        ModifyIndex: 136,
        ModifyTime: 1647901211369648000,
        Namespace: 'default',
        NextEval: '',
        NodeID: '',
        PreviousEval: '25a2dd19-8d22-d1dd-280a-79860c9b8bdb',
        Priority: 50,
        Status: 'pending',
        StatusDescription: '',
        TriggeredBy: 'failed-follow-up',
        Type: 'service',
        WaitUntil: null,
      },
    ],
    Status: 'failed',
    StatusDescription: 'evaluation reached delivery limit (3)',
    TriggeredBy: 'failed-follow-up',
    Type: 'service',
    Wait: 20000000000,
  };
};

export const MOCK_EVALUATION = {
  CreateIndex: 20,
  CreateTime: 1647899150314738000,
  ID: 'fede162c-26a6-c108-178b-1c140f9f5680',
  JobID: 'example',
  JobModifyIndex: 10,
  ModifyIndex: 31,
  ModifyTime: 1647899318007569000,
  Namespace: 'default',
  NextEval: 'fd1cd898-d655-c7e4-17f6-a1a2e98b18ef',
  PreviousEval: 'd8a5c14f-120a-3d83-6305-90927356dd6c',
  Priority: 50,
  RelatedEvals: [
    {
      BlockedEval: '',
      CreateIndex: 31,
      CreateTime: 1647899318007563000,
      DeploymentID: '',
      ID: 'fd1cd898-d655-c7e4-17f6-a1a2e98b18ef',
      JobID: 'example',
      ModifyIndex: 44,
      ModifyTime: 1647899591412413000,
      Namespace: 'default',
      NextEval: 'cac7dfa0-b79b-ee55-c86a-0ca89dffb9e1',
      NodeID: '',
      PreviousEval: 'fede162c-26a6-c108-178b-1c140f9f5680',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 10,
      CreateTime: 1647899129298997000,
      DeploymentID: '',
      ID: 'd8a5c14f-120a-3d83-6305-90927356dd6c',
      JobID: 'example',
      ModifyIndex: 20,
      ModifyTime: 1647899150314745000,
      Namespace: 'default',
      NextEval: 'fede162c-26a6-c108-178b-1c140f9f5680',
      NodeID: '',
      PreviousEval: '',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'job-register',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 44,
      CreateTime: 1647899591412410000,
      DeploymentID: '',
      ID: 'cac7dfa0-b79b-ee55-c86a-0ca89dffb9e1',
      JobID: 'example',
      ModifyIndex: 53,
      ModifyTime: 1647899729480596000,
      Namespace: 'default',
      NextEval: 'e49bf53c-da6a-c869-8317-f2089682f503',
      NodeID: '',
      PreviousEval: 'fd1cd898-d655-c7e4-17f6-a1a2e98b18ef',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 53,
      CreateTime: 1647899729480592000,
      DeploymentID: '',
      ID: 'e49bf53c-da6a-c869-8317-f2089682f503',
      JobID: 'example',
      ModifyIndex: 64,
      ModifyTime: 1647899881302731000,
      Namespace: 'default',
      NextEval: 'a8d29cfc-517c-2e4c-9722-b47e84152c64',
      NodeID: '',
      PreviousEval: 'cac7dfa0-b79b-ee55-c86a-0ca89dffb9e1',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 64,
      CreateTime: 1647899881302723000,
      DeploymentID: '',
      ID: 'a8d29cfc-517c-2e4c-9722-b47e84152c64',
      JobID: 'example',
      ModifyIndex: 81,
      ModifyTime: 1647900212725381000,
      Namespace: 'default',
      NextEval: 'b37d06e4-4eb4-b29d-3b4a-b0c7bf2528ad',
      NodeID: '',
      PreviousEval: 'e49bf53c-da6a-c869-8317-f2089682f503',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 81,
      CreateTime: 1647900212725376000,
      DeploymentID: '',
      ID: 'b37d06e4-4eb4-b29d-3b4a-b0c7bf2528ad',
      JobID: 'example',
      ModifyIndex: 97,
      ModifyTime: 1647900516944239000,
      Namespace: 'default',
      NextEval: 'd7c50aa5-5bf1-5119-d7e7-0d0ae5381856',
      NodeID: '',
      PreviousEval: 'a8d29cfc-517c-2e4c-9722-b47e84152c64',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 97,
      CreateTime: 1647900516944236000,
      DeploymentID: '',
      ID: 'd7c50aa5-5bf1-5119-d7e7-0d0ae5381856',
      JobID: 'example',
      ModifyIndex: 114,
      ModifyTime: 1647900825385587000,
      Namespace: 'default',
      NextEval: 'ea2239aa-26d6-8874-8c56-e1600585772b',
      NodeID: '',
      PreviousEval: 'b37d06e4-4eb4-b29d-3b4a-b0c7bf2528ad',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 114,
      CreateTime: 1647900825385584000,
      DeploymentID: '',
      ID: 'ea2239aa-26d6-8874-8c56-e1600585772b',
      JobID: 'example',
      ModifyIndex: 128,
      ModifyTime: 1647900979511304000,
      Namespace: 'default',
      NextEval: '25a2dd19-8d22-d1dd-280a-79860c9b8bdb',
      NodeID: '',
      PreviousEval: 'd7c50aa5-5bf1-5119-d7e7-0d0ae5381856',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 128,
      CreateTime: 1647900979511301000,
      DeploymentID: '',
      ID: '25a2dd19-8d22-d1dd-280a-79860c9b8bdb',
      JobID: 'example',
      ModifyIndex: 136,
      ModifyTime: 1647901211369652000,
      Namespace: 'default',
      NextEval: '1fded690-20ad-6afa-3b89-59e319dfce18',
      NodeID: '',
      PreviousEval: 'ea2239aa-26d6-8874-8c56-e1600585772b',
      Priority: 50,
      Status: 'failed',
      StatusDescription: 'evaluation reached delivery limit (3)',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
    {
      BlockedEval: '',
      CreateIndex: 136,
      CreateTime: 1647901211369648000,
      DeploymentID: '',
      ID: '1fded690-20ad-6afa-3b89-59e319dfce18',
      JobID: 'example',
      ModifyIndex: 136,
      ModifyTime: 1647901211369648000,
      Namespace: 'default',
      NextEval: '',
      NodeID: '',
      PreviousEval: '25a2dd19-8d22-d1dd-280a-79860c9b8bdb',
      Priority: 50,
      Status: 'pending',
      StatusDescription: '',
      TriggeredBy: 'failed-follow-up',
      Type: 'service',
      WaitUntil: null,
    },
  ],
  Status: 'failed',
  StatusDescription: 'evaluation reached delivery limit (3)',
  TriggeredBy: 'failed-follow-up',
  Type: 'service',
  Wait: 20000000000,
};
