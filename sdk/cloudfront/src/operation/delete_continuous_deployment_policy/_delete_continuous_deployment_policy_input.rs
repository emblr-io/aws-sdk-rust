// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteContinuousDeploymentPolicyInput {
    /// <p>The identifier of the continuous deployment policy that you are deleting.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The current version (<code>ETag</code> value) of the continuous deployment policy that you are deleting.</p>
    pub if_match: ::std::option::Option<::std::string::String>,
}
impl DeleteContinuousDeploymentPolicyInput {
    /// <p>The identifier of the continuous deployment policy that you are deleting.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The current version (<code>ETag</code> value) of the continuous deployment policy that you are deleting.</p>
    pub fn if_match(&self) -> ::std::option::Option<&str> {
        self.if_match.as_deref()
    }
}
impl DeleteContinuousDeploymentPolicyInput {
    /// Creates a new builder-style object to manufacture [`DeleteContinuousDeploymentPolicyInput`](crate::operation::delete_continuous_deployment_policy::DeleteContinuousDeploymentPolicyInput).
    pub fn builder() -> crate::operation::delete_continuous_deployment_policy::builders::DeleteContinuousDeploymentPolicyInputBuilder {
        crate::operation::delete_continuous_deployment_policy::builders::DeleteContinuousDeploymentPolicyInputBuilder::default()
    }
}

/// A builder for [`DeleteContinuousDeploymentPolicyInput`](crate::operation::delete_continuous_deployment_policy::DeleteContinuousDeploymentPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteContinuousDeploymentPolicyInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) if_match: ::std::option::Option<::std::string::String>,
}
impl DeleteContinuousDeploymentPolicyInputBuilder {
    /// <p>The identifier of the continuous deployment policy that you are deleting.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the continuous deployment policy that you are deleting.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the continuous deployment policy that you are deleting.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The current version (<code>ETag</code> value) of the continuous deployment policy that you are deleting.</p>
    pub fn if_match(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.if_match = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version (<code>ETag</code> value) of the continuous deployment policy that you are deleting.</p>
    pub fn set_if_match(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.if_match = input;
        self
    }
    /// <p>The current version (<code>ETag</code> value) of the continuous deployment policy that you are deleting.</p>
    pub fn get_if_match(&self) -> &::std::option::Option<::std::string::String> {
        &self.if_match
    }
    /// Consumes the builder and constructs a [`DeleteContinuousDeploymentPolicyInput`](crate::operation::delete_continuous_deployment_policy::DeleteContinuousDeploymentPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_continuous_deployment_policy::DeleteContinuousDeploymentPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_continuous_deployment_policy::DeleteContinuousDeploymentPolicyInput {
                id: self.id,
                if_match: self.if_match,
            },
        )
    }
}
