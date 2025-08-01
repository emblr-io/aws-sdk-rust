// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeServiceDeploymentsInput {
    /// <p>The ARN of the service deployment.</p>
    /// <p>You can specify a maximum of 20 ARNs.</p>
    pub service_deployment_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeServiceDeploymentsInput {
    /// <p>The ARN of the service deployment.</p>
    /// <p>You can specify a maximum of 20 ARNs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.service_deployment_arns.is_none()`.
    pub fn service_deployment_arns(&self) -> &[::std::string::String] {
        self.service_deployment_arns.as_deref().unwrap_or_default()
    }
}
impl DescribeServiceDeploymentsInput {
    /// Creates a new builder-style object to manufacture [`DescribeServiceDeploymentsInput`](crate::operation::describe_service_deployments::DescribeServiceDeploymentsInput).
    pub fn builder() -> crate::operation::describe_service_deployments::builders::DescribeServiceDeploymentsInputBuilder {
        crate::operation::describe_service_deployments::builders::DescribeServiceDeploymentsInputBuilder::default()
    }
}

/// A builder for [`DescribeServiceDeploymentsInput`](crate::operation::describe_service_deployments::DescribeServiceDeploymentsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeServiceDeploymentsInputBuilder {
    pub(crate) service_deployment_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeServiceDeploymentsInputBuilder {
    /// Appends an item to `service_deployment_arns`.
    ///
    /// To override the contents of this collection use [`set_service_deployment_arns`](Self::set_service_deployment_arns).
    ///
    /// <p>The ARN of the service deployment.</p>
    /// <p>You can specify a maximum of 20 ARNs.</p>
    pub fn service_deployment_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.service_deployment_arns.unwrap_or_default();
        v.push(input.into());
        self.service_deployment_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARN of the service deployment.</p>
    /// <p>You can specify a maximum of 20 ARNs.</p>
    pub fn set_service_deployment_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.service_deployment_arns = input;
        self
    }
    /// <p>The ARN of the service deployment.</p>
    /// <p>You can specify a maximum of 20 ARNs.</p>
    pub fn get_service_deployment_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.service_deployment_arns
    }
    /// Consumes the builder and constructs a [`DescribeServiceDeploymentsInput`](crate::operation::describe_service_deployments::DescribeServiceDeploymentsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_service_deployments::DescribeServiceDeploymentsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_service_deployments::DescribeServiceDeploymentsInput {
            service_deployment_arns: self.service_deployment_arns,
        })
    }
}
