// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTemplatePermissionsInput {
    /// <p>The ID of the Amazon Web Services account that contains the template that you're describing.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the template.</p>
    pub template_id: ::std::option::Option<::std::string::String>,
}
impl DescribeTemplatePermissionsInput {
    /// <p>The ID of the Amazon Web Services account that contains the template that you're describing.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID for the template.</p>
    pub fn template_id(&self) -> ::std::option::Option<&str> {
        self.template_id.as_deref()
    }
}
impl DescribeTemplatePermissionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeTemplatePermissionsInput`](crate::operation::describe_template_permissions::DescribeTemplatePermissionsInput).
    pub fn builder() -> crate::operation::describe_template_permissions::builders::DescribeTemplatePermissionsInputBuilder {
        crate::operation::describe_template_permissions::builders::DescribeTemplatePermissionsInputBuilder::default()
    }
}

/// A builder for [`DescribeTemplatePermissionsInput`](crate::operation::describe_template_permissions::DescribeTemplatePermissionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTemplatePermissionsInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) template_id: ::std::option::Option<::std::string::String>,
}
impl DescribeTemplatePermissionsInputBuilder {
    /// <p>The ID of the Amazon Web Services account that contains the template that you're describing.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the template that you're describing.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account that contains the template that you're describing.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID for the template.</p>
    /// This field is required.
    pub fn template_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the template.</p>
    pub fn set_template_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_id = input;
        self
    }
    /// <p>The ID for the template.</p>
    pub fn get_template_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_id
    }
    /// Consumes the builder and constructs a [`DescribeTemplatePermissionsInput`](crate::operation::describe_template_permissions::DescribeTemplatePermissionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_template_permissions::DescribeTemplatePermissionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_template_permissions::DescribeTemplatePermissionsInput {
            aws_account_id: self.aws_account_id,
            template_id: self.template_id,
        })
    }
}
