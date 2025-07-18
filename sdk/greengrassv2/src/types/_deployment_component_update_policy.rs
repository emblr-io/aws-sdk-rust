// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a deployment's policy that defines when components are safe to update.</p>
/// <p>Each component on a device can report whether or not it's ready to update. After a component and its dependencies are ready, they can apply the update in the deployment. You can configure whether or not the deployment notifies components of an update and waits for a response. You specify the amount of time each component has to respond to the update notification.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeploymentComponentUpdatePolicy {
    /// <p>The amount of time in seconds that each component on a device has to report that it's safe to update. If the component waits for longer than this timeout, then the deployment proceeds on the device.</p>
    /// <p>Default: <code>60</code></p>
    pub timeout_in_seconds: ::std::option::Option<i32>,
    /// <p>Whether or not to notify components and wait for components to become safe to update. Choose from the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>NOTIFY_COMPONENTS</code> – The deployment notifies each component before it stops and updates that component. Components can use the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-subscribetocomponentupdates">SubscribeToComponentUpdates</a> IPC operation to receive these notifications. Then, components can respond with the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-defercomponentupdate">DeferComponentUpdate</a> IPC operation. For more information, see <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/create-deployments.html">Create deployments</a> in the <i>IoT Greengrass V2 Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>SKIP_NOTIFY_COMPONENTS</code> – The deployment doesn't notify components or wait for them to be safe to update.</p></li>
    /// </ul>
    /// <p>Default: <code>NOTIFY_COMPONENTS</code></p>
    pub action: ::std::option::Option<crate::types::DeploymentComponentUpdatePolicyAction>,
}
impl DeploymentComponentUpdatePolicy {
    /// <p>The amount of time in seconds that each component on a device has to report that it's safe to update. If the component waits for longer than this timeout, then the deployment proceeds on the device.</p>
    /// <p>Default: <code>60</code></p>
    pub fn timeout_in_seconds(&self) -> ::std::option::Option<i32> {
        self.timeout_in_seconds
    }
    /// <p>Whether or not to notify components and wait for components to become safe to update. Choose from the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>NOTIFY_COMPONENTS</code> – The deployment notifies each component before it stops and updates that component. Components can use the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-subscribetocomponentupdates">SubscribeToComponentUpdates</a> IPC operation to receive these notifications. Then, components can respond with the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-defercomponentupdate">DeferComponentUpdate</a> IPC operation. For more information, see <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/create-deployments.html">Create deployments</a> in the <i>IoT Greengrass V2 Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>SKIP_NOTIFY_COMPONENTS</code> – The deployment doesn't notify components or wait for them to be safe to update.</p></li>
    /// </ul>
    /// <p>Default: <code>NOTIFY_COMPONENTS</code></p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::DeploymentComponentUpdatePolicyAction> {
        self.action.as_ref()
    }
}
impl DeploymentComponentUpdatePolicy {
    /// Creates a new builder-style object to manufacture [`DeploymentComponentUpdatePolicy`](crate::types::DeploymentComponentUpdatePolicy).
    pub fn builder() -> crate::types::builders::DeploymentComponentUpdatePolicyBuilder {
        crate::types::builders::DeploymentComponentUpdatePolicyBuilder::default()
    }
}

/// A builder for [`DeploymentComponentUpdatePolicy`](crate::types::DeploymentComponentUpdatePolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeploymentComponentUpdatePolicyBuilder {
    pub(crate) timeout_in_seconds: ::std::option::Option<i32>,
    pub(crate) action: ::std::option::Option<crate::types::DeploymentComponentUpdatePolicyAction>,
}
impl DeploymentComponentUpdatePolicyBuilder {
    /// <p>The amount of time in seconds that each component on a device has to report that it's safe to update. If the component waits for longer than this timeout, then the deployment proceeds on the device.</p>
    /// <p>Default: <code>60</code></p>
    pub fn timeout_in_seconds(mut self, input: i32) -> Self {
        self.timeout_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time in seconds that each component on a device has to report that it's safe to update. If the component waits for longer than this timeout, then the deployment proceeds on the device.</p>
    /// <p>Default: <code>60</code></p>
    pub fn set_timeout_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.timeout_in_seconds = input;
        self
    }
    /// <p>The amount of time in seconds that each component on a device has to report that it's safe to update. If the component waits for longer than this timeout, then the deployment proceeds on the device.</p>
    /// <p>Default: <code>60</code></p>
    pub fn get_timeout_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.timeout_in_seconds
    }
    /// <p>Whether or not to notify components and wait for components to become safe to update. Choose from the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>NOTIFY_COMPONENTS</code> – The deployment notifies each component before it stops and updates that component. Components can use the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-subscribetocomponentupdates">SubscribeToComponentUpdates</a> IPC operation to receive these notifications. Then, components can respond with the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-defercomponentupdate">DeferComponentUpdate</a> IPC operation. For more information, see <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/create-deployments.html">Create deployments</a> in the <i>IoT Greengrass V2 Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>SKIP_NOTIFY_COMPONENTS</code> – The deployment doesn't notify components or wait for them to be safe to update.</p></li>
    /// </ul>
    /// <p>Default: <code>NOTIFY_COMPONENTS</code></p>
    pub fn action(mut self, input: crate::types::DeploymentComponentUpdatePolicyAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether or not to notify components and wait for components to become safe to update. Choose from the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>NOTIFY_COMPONENTS</code> – The deployment notifies each component before it stops and updates that component. Components can use the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-subscribetocomponentupdates">SubscribeToComponentUpdates</a> IPC operation to receive these notifications. Then, components can respond with the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-defercomponentupdate">DeferComponentUpdate</a> IPC operation. For more information, see <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/create-deployments.html">Create deployments</a> in the <i>IoT Greengrass V2 Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>SKIP_NOTIFY_COMPONENTS</code> – The deployment doesn't notify components or wait for them to be safe to update.</p></li>
    /// </ul>
    /// <p>Default: <code>NOTIFY_COMPONENTS</code></p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::DeploymentComponentUpdatePolicyAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>Whether or not to notify components and wait for components to become safe to update. Choose from the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>NOTIFY_COMPONENTS</code> – The deployment notifies each component before it stops and updates that component. Components can use the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-subscribetocomponentupdates">SubscribeToComponentUpdates</a> IPC operation to receive these notifications. Then, components can respond with the <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/interprocess-communication.html#ipc-operation-defercomponentupdate">DeferComponentUpdate</a> IPC operation. For more information, see <a href="https://docs.aws.amazon.com/greengrass/v2/developerguide/create-deployments.html">Create deployments</a> in the <i>IoT Greengrass V2 Developer Guide</i>.</p></li>
    /// <li>
    /// <p><code>SKIP_NOTIFY_COMPONENTS</code> – The deployment doesn't notify components or wait for them to be safe to update.</p></li>
    /// </ul>
    /// <p>Default: <code>NOTIFY_COMPONENTS</code></p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::DeploymentComponentUpdatePolicyAction> {
        &self.action
    }
    /// Consumes the builder and constructs a [`DeploymentComponentUpdatePolicy`](crate::types::DeploymentComponentUpdatePolicy).
    pub fn build(self) -> crate::types::DeploymentComponentUpdatePolicy {
        crate::types::DeploymentComponentUpdatePolicy {
            timeout_in_seconds: self.timeout_in_seconds,
            action: self.action,
        }
    }
}
