// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDataSetInput {
    /// <p>The Amazon Web Services account ID.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the dataset that you want to create. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub data_set_id: ::std::option::Option<::std::string::String>,
}
impl DescribeDataSetInput {
    /// <p>The Amazon Web Services account ID.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID for the dataset that you want to create. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn data_set_id(&self) -> ::std::option::Option<&str> {
        self.data_set_id.as_deref()
    }
}
impl DescribeDataSetInput {
    /// Creates a new builder-style object to manufacture [`DescribeDataSetInput`](crate::operation::describe_data_set::DescribeDataSetInput).
    pub fn builder() -> crate::operation::describe_data_set::builders::DescribeDataSetInputBuilder {
        crate::operation::describe_data_set::builders::DescribeDataSetInputBuilder::default()
    }
}

/// A builder for [`DescribeDataSetInput`](crate::operation::describe_data_set::DescribeDataSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDataSetInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_set_id: ::std::option::Option<::std::string::String>,
}
impl DescribeDataSetInputBuilder {
    /// <p>The Amazon Web Services account ID.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID for the dataset that you want to create. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    /// This field is required.
    pub fn data_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the dataset that you want to create. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn set_data_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_id = input;
        self
    }
    /// <p>The ID for the dataset that you want to create. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn get_data_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_id
    }
    /// Consumes the builder and constructs a [`DescribeDataSetInput`](crate::operation::describe_data_set::DescribeDataSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_data_set::DescribeDataSetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_data_set::DescribeDataSetInput {
            aws_account_id: self.aws_account_id,
            data_set_id: self.data_set_id,
        })
    }
}
