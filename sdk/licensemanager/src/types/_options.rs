// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The options you can specify when you create a new version of a grant, such as activation override behavior. For more information, see <a href="https://docs.aws.amazon.com/license-manager/latest/userguide/granted-licenses.html">Granted licenses in License Manager</a> in the <i>License Manager User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Options {
    /// <p>An activation option for your grant that determines the behavior of activating a grant. Activation options can only be used with granted licenses sourced from the Amazon Web Services Marketplace. Additionally, the operation must specify the value of <code>ACTIVE</code> for the <code>Status</code> parameter.</p>
    /// <ul>
    /// <li>
    /// <p>As a license administrator, you can optionally specify an <code>ActivationOverrideBehavior</code> when activating a grant.</p></li>
    /// <li>
    /// <p>As a grantor, you can optionally specify an <code>ActivationOverrideBehavior</code> when you activate a grant for a grantee account in your organization.</p></li>
    /// <li>
    /// <p>As a grantee, if the grantor creating the distributed grant doesn’t specify an <code>ActivationOverrideBehavior</code>, you can optionally specify one when you are activating the grant.</p></li>
    /// </ul>
    /// <dl>
    /// <dt>
    /// DISTRIBUTED_GRANTS_ONLY
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant without replacing any member account’s active grants for the same product.</p>
    /// </dd>
    /// <dt>
    /// ALL_GRANTS_PERMITTED_BY_ISSUER
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant and disable other active grants in any member accounts for the same product. This action will also replace their previously activated grants with this activated grant.</p>
    /// </dd>
    /// </dl>
    pub activation_override_behavior: ::std::option::Option<crate::types::ActivationOverrideBehavior>,
}
impl Options {
    /// <p>An activation option for your grant that determines the behavior of activating a grant. Activation options can only be used with granted licenses sourced from the Amazon Web Services Marketplace. Additionally, the operation must specify the value of <code>ACTIVE</code> for the <code>Status</code> parameter.</p>
    /// <ul>
    /// <li>
    /// <p>As a license administrator, you can optionally specify an <code>ActivationOverrideBehavior</code> when activating a grant.</p></li>
    /// <li>
    /// <p>As a grantor, you can optionally specify an <code>ActivationOverrideBehavior</code> when you activate a grant for a grantee account in your organization.</p></li>
    /// <li>
    /// <p>As a grantee, if the grantor creating the distributed grant doesn’t specify an <code>ActivationOverrideBehavior</code>, you can optionally specify one when you are activating the grant.</p></li>
    /// </ul>
    /// <dl>
    /// <dt>
    /// DISTRIBUTED_GRANTS_ONLY
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant without replacing any member account’s active grants for the same product.</p>
    /// </dd>
    /// <dt>
    /// ALL_GRANTS_PERMITTED_BY_ISSUER
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant and disable other active grants in any member accounts for the same product. This action will also replace their previously activated grants with this activated grant.</p>
    /// </dd>
    /// </dl>
    pub fn activation_override_behavior(&self) -> ::std::option::Option<&crate::types::ActivationOverrideBehavior> {
        self.activation_override_behavior.as_ref()
    }
}
impl Options {
    /// Creates a new builder-style object to manufacture [`Options`](crate::types::Options).
    pub fn builder() -> crate::types::builders::OptionsBuilder {
        crate::types::builders::OptionsBuilder::default()
    }
}

/// A builder for [`Options`](crate::types::Options).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OptionsBuilder {
    pub(crate) activation_override_behavior: ::std::option::Option<crate::types::ActivationOverrideBehavior>,
}
impl OptionsBuilder {
    /// <p>An activation option for your grant that determines the behavior of activating a grant. Activation options can only be used with granted licenses sourced from the Amazon Web Services Marketplace. Additionally, the operation must specify the value of <code>ACTIVE</code> for the <code>Status</code> parameter.</p>
    /// <ul>
    /// <li>
    /// <p>As a license administrator, you can optionally specify an <code>ActivationOverrideBehavior</code> when activating a grant.</p></li>
    /// <li>
    /// <p>As a grantor, you can optionally specify an <code>ActivationOverrideBehavior</code> when you activate a grant for a grantee account in your organization.</p></li>
    /// <li>
    /// <p>As a grantee, if the grantor creating the distributed grant doesn’t specify an <code>ActivationOverrideBehavior</code>, you can optionally specify one when you are activating the grant.</p></li>
    /// </ul>
    /// <dl>
    /// <dt>
    /// DISTRIBUTED_GRANTS_ONLY
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant without replacing any member account’s active grants for the same product.</p>
    /// </dd>
    /// <dt>
    /// ALL_GRANTS_PERMITTED_BY_ISSUER
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant and disable other active grants in any member accounts for the same product. This action will also replace their previously activated grants with this activated grant.</p>
    /// </dd>
    /// </dl>
    pub fn activation_override_behavior(mut self, input: crate::types::ActivationOverrideBehavior) -> Self {
        self.activation_override_behavior = ::std::option::Option::Some(input);
        self
    }
    /// <p>An activation option for your grant that determines the behavior of activating a grant. Activation options can only be used with granted licenses sourced from the Amazon Web Services Marketplace. Additionally, the operation must specify the value of <code>ACTIVE</code> for the <code>Status</code> parameter.</p>
    /// <ul>
    /// <li>
    /// <p>As a license administrator, you can optionally specify an <code>ActivationOverrideBehavior</code> when activating a grant.</p></li>
    /// <li>
    /// <p>As a grantor, you can optionally specify an <code>ActivationOverrideBehavior</code> when you activate a grant for a grantee account in your organization.</p></li>
    /// <li>
    /// <p>As a grantee, if the grantor creating the distributed grant doesn’t specify an <code>ActivationOverrideBehavior</code>, you can optionally specify one when you are activating the grant.</p></li>
    /// </ul>
    /// <dl>
    /// <dt>
    /// DISTRIBUTED_GRANTS_ONLY
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant without replacing any member account’s active grants for the same product.</p>
    /// </dd>
    /// <dt>
    /// ALL_GRANTS_PERMITTED_BY_ISSUER
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant and disable other active grants in any member accounts for the same product. This action will also replace their previously activated grants with this activated grant.</p>
    /// </dd>
    /// </dl>
    pub fn set_activation_override_behavior(mut self, input: ::std::option::Option<crate::types::ActivationOverrideBehavior>) -> Self {
        self.activation_override_behavior = input;
        self
    }
    /// <p>An activation option for your grant that determines the behavior of activating a grant. Activation options can only be used with granted licenses sourced from the Amazon Web Services Marketplace. Additionally, the operation must specify the value of <code>ACTIVE</code> for the <code>Status</code> parameter.</p>
    /// <ul>
    /// <li>
    /// <p>As a license administrator, you can optionally specify an <code>ActivationOverrideBehavior</code> when activating a grant.</p></li>
    /// <li>
    /// <p>As a grantor, you can optionally specify an <code>ActivationOverrideBehavior</code> when you activate a grant for a grantee account in your organization.</p></li>
    /// <li>
    /// <p>As a grantee, if the grantor creating the distributed grant doesn’t specify an <code>ActivationOverrideBehavior</code>, you can optionally specify one when you are activating the grant.</p></li>
    /// </ul>
    /// <dl>
    /// <dt>
    /// DISTRIBUTED_GRANTS_ONLY
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant without replacing any member account’s active grants for the same product.</p>
    /// </dd>
    /// <dt>
    /// ALL_GRANTS_PERMITTED_BY_ISSUER
    /// </dt>
    /// <dd>
    /// <p>Use this value to activate a grant and disable other active grants in any member accounts for the same product. This action will also replace their previously activated grants with this activated grant.</p>
    /// </dd>
    /// </dl>
    pub fn get_activation_override_behavior(&self) -> &::std::option::Option<crate::types::ActivationOverrideBehavior> {
        &self.activation_override_behavior
    }
    /// Consumes the builder and constructs a [`Options`](crate::types::Options).
    pub fn build(self) -> crate::types::Options {
        crate::types::Options {
            activation_override_behavior: self.activation_override_behavior,
        }
    }
}
