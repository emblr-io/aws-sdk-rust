// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeServiceActionExecutionParametersInput {
    /// <p>The identifier of the provisioned product.</p>
    pub provisioned_product_id: ::std::option::Option<::std::string::String>,
    /// <p>The self-service action identifier.</p>
    pub service_action_id: ::std::option::Option<::std::string::String>,
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
}
impl DescribeServiceActionExecutionParametersInput {
    /// <p>The identifier of the provisioned product.</p>
    pub fn provisioned_product_id(&self) -> ::std::option::Option<&str> {
        self.provisioned_product_id.as_deref()
    }
    /// <p>The self-service action identifier.</p>
    pub fn service_action_id(&self) -> ::std::option::Option<&str> {
        self.service_action_id.as_deref()
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(&self) -> ::std::option::Option<&str> {
        self.accept_language.as_deref()
    }
}
impl DescribeServiceActionExecutionParametersInput {
    /// Creates a new builder-style object to manufacture [`DescribeServiceActionExecutionParametersInput`](crate::operation::describe_service_action_execution_parameters::DescribeServiceActionExecutionParametersInput).
    pub fn builder() -> crate::operation::describe_service_action_execution_parameters::builders::DescribeServiceActionExecutionParametersInputBuilder
    {
        crate::operation::describe_service_action_execution_parameters::builders::DescribeServiceActionExecutionParametersInputBuilder::default()
    }
}

/// A builder for [`DescribeServiceActionExecutionParametersInput`](crate::operation::describe_service_action_execution_parameters::DescribeServiceActionExecutionParametersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeServiceActionExecutionParametersInputBuilder {
    pub(crate) provisioned_product_id: ::std::option::Option<::std::string::String>,
    pub(crate) service_action_id: ::std::option::Option<::std::string::String>,
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
}
impl DescribeServiceActionExecutionParametersInputBuilder {
    /// <p>The identifier of the provisioned product.</p>
    /// This field is required.
    pub fn provisioned_product_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provisioned_product_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the provisioned product.</p>
    pub fn set_provisioned_product_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provisioned_product_id = input;
        self
    }
    /// <p>The identifier of the provisioned product.</p>
    pub fn get_provisioned_product_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.provisioned_product_id
    }
    /// <p>The self-service action identifier.</p>
    /// This field is required.
    pub fn service_action_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_action_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The self-service action identifier.</p>
    pub fn set_service_action_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_action_id = input;
        self
    }
    /// <p>The self-service action identifier.</p>
    pub fn get_service_action_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_action_id
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accept_language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn set_accept_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accept_language = input;
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn get_accept_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.accept_language
    }
    /// Consumes the builder and constructs a [`DescribeServiceActionExecutionParametersInput`](crate::operation::describe_service_action_execution_parameters::DescribeServiceActionExecutionParametersInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_service_action_execution_parameters::DescribeServiceActionExecutionParametersInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_service_action_execution_parameters::DescribeServiceActionExecutionParametersInput {
                provisioned_product_id: self.provisioned_product_id,
                service_action_id: self.service_action_id,
                accept_language: self.accept_language,
            },
        )
    }
}
