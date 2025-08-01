// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutAutoTerminationPolicyInput {
    /// <p>Specifies the ID of the Amazon EMR cluster to which the auto-termination policy will be attached.</p>
    pub cluster_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the auto-termination policy to attach to the cluster.</p>
    pub auto_termination_policy: ::std::option::Option<crate::types::AutoTerminationPolicy>,
}
impl PutAutoTerminationPolicyInput {
    /// <p>Specifies the ID of the Amazon EMR cluster to which the auto-termination policy will be attached.</p>
    pub fn cluster_id(&self) -> ::std::option::Option<&str> {
        self.cluster_id.as_deref()
    }
    /// <p>Specifies the auto-termination policy to attach to the cluster.</p>
    pub fn auto_termination_policy(&self) -> ::std::option::Option<&crate::types::AutoTerminationPolicy> {
        self.auto_termination_policy.as_ref()
    }
}
impl PutAutoTerminationPolicyInput {
    /// Creates a new builder-style object to manufacture [`PutAutoTerminationPolicyInput`](crate::operation::put_auto_termination_policy::PutAutoTerminationPolicyInput).
    pub fn builder() -> crate::operation::put_auto_termination_policy::builders::PutAutoTerminationPolicyInputBuilder {
        crate::operation::put_auto_termination_policy::builders::PutAutoTerminationPolicyInputBuilder::default()
    }
}

/// A builder for [`PutAutoTerminationPolicyInput`](crate::operation::put_auto_termination_policy::PutAutoTerminationPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutAutoTerminationPolicyInputBuilder {
    pub(crate) cluster_id: ::std::option::Option<::std::string::String>,
    pub(crate) auto_termination_policy: ::std::option::Option<crate::types::AutoTerminationPolicy>,
}
impl PutAutoTerminationPolicyInputBuilder {
    /// <p>Specifies the ID of the Amazon EMR cluster to which the auto-termination policy will be attached.</p>
    /// This field is required.
    pub fn cluster_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ID of the Amazon EMR cluster to which the auto-termination policy will be attached.</p>
    pub fn set_cluster_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_id = input;
        self
    }
    /// <p>Specifies the ID of the Amazon EMR cluster to which the auto-termination policy will be attached.</p>
    pub fn get_cluster_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_id
    }
    /// <p>Specifies the auto-termination policy to attach to the cluster.</p>
    pub fn auto_termination_policy(mut self, input: crate::types::AutoTerminationPolicy) -> Self {
        self.auto_termination_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the auto-termination policy to attach to the cluster.</p>
    pub fn set_auto_termination_policy(mut self, input: ::std::option::Option<crate::types::AutoTerminationPolicy>) -> Self {
        self.auto_termination_policy = input;
        self
    }
    /// <p>Specifies the auto-termination policy to attach to the cluster.</p>
    pub fn get_auto_termination_policy(&self) -> &::std::option::Option<crate::types::AutoTerminationPolicy> {
        &self.auto_termination_policy
    }
    /// Consumes the builder and constructs a [`PutAutoTerminationPolicyInput`](crate::operation::put_auto_termination_policy::PutAutoTerminationPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_auto_termination_policy::PutAutoTerminationPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_auto_termination_policy::PutAutoTerminationPolicyInput {
            cluster_id: self.cluster_id,
            auto_termination_policy: self.auto_termination_policy,
        })
    }
}
