// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDeploymentsInput {
    /// <p>The stack ID. If you include this parameter, the command returns a description of the commands associated with the specified stack.</p>
    pub stack_id: ::std::option::Option<::std::string::String>,
    /// <p>The app ID. If you include this parameter, the command returns a description of the commands associated with the specified app.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>An array of deployment IDs to be described. If you include this parameter, the command returns a description of the specified deployments. Otherwise, it returns a description of every deployment.</p>
    pub deployment_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeDeploymentsInput {
    /// <p>The stack ID. If you include this parameter, the command returns a description of the commands associated with the specified stack.</p>
    pub fn stack_id(&self) -> ::std::option::Option<&str> {
        self.stack_id.as_deref()
    }
    /// <p>The app ID. If you include this parameter, the command returns a description of the commands associated with the specified app.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>An array of deployment IDs to be described. If you include this parameter, the command returns a description of the specified deployments. Otherwise, it returns a description of every deployment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.deployment_ids.is_none()`.
    pub fn deployment_ids(&self) -> &[::std::string::String] {
        self.deployment_ids.as_deref().unwrap_or_default()
    }
}
impl DescribeDeploymentsInput {
    /// Creates a new builder-style object to manufacture [`DescribeDeploymentsInput`](crate::operation::describe_deployments::DescribeDeploymentsInput).
    pub fn builder() -> crate::operation::describe_deployments::builders::DescribeDeploymentsInputBuilder {
        crate::operation::describe_deployments::builders::DescribeDeploymentsInputBuilder::default()
    }
}

/// A builder for [`DescribeDeploymentsInput`](crate::operation::describe_deployments::DescribeDeploymentsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDeploymentsInputBuilder {
    pub(crate) stack_id: ::std::option::Option<::std::string::String>,
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeDeploymentsInputBuilder {
    /// <p>The stack ID. If you include this parameter, the command returns a description of the commands associated with the specified stack.</p>
    pub fn stack_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stack ID. If you include this parameter, the command returns a description of the commands associated with the specified stack.</p>
    pub fn set_stack_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_id = input;
        self
    }
    /// <p>The stack ID. If you include this parameter, the command returns a description of the commands associated with the specified stack.</p>
    pub fn get_stack_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_id
    }
    /// <p>The app ID. If you include this parameter, the command returns a description of the commands associated with the specified app.</p>
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The app ID. If you include this parameter, the command returns a description of the commands associated with the specified app.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The app ID. If you include this parameter, the command returns a description of the commands associated with the specified app.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// Appends an item to `deployment_ids`.
    ///
    /// To override the contents of this collection use [`set_deployment_ids`](Self::set_deployment_ids).
    ///
    /// <p>An array of deployment IDs to be described. If you include this parameter, the command returns a description of the specified deployments. Otherwise, it returns a description of every deployment.</p>
    pub fn deployment_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.deployment_ids.unwrap_or_default();
        v.push(input.into());
        self.deployment_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of deployment IDs to be described. If you include this parameter, the command returns a description of the specified deployments. Otherwise, it returns a description of every deployment.</p>
    pub fn set_deployment_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.deployment_ids = input;
        self
    }
    /// <p>An array of deployment IDs to be described. If you include this parameter, the command returns a description of the specified deployments. Otherwise, it returns a description of every deployment.</p>
    pub fn get_deployment_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.deployment_ids
    }
    /// Consumes the builder and constructs a [`DescribeDeploymentsInput`](crate::operation::describe_deployments::DescribeDeploymentsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_deployments::DescribeDeploymentsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_deployments::DescribeDeploymentsInput {
            stack_id: self.stack_id,
            app_id: self.app_id,
            deployment_ids: self.deployment_ids,
        })
    }
}
