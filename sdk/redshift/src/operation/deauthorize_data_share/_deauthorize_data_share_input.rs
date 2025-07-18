// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeauthorizeDataShareInput {
    /// <p>The namespace Amazon Resource Name (ARN) of the datashare to remove authorization from.</p>
    pub data_share_arn: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the data consumer that is to have authorization removed from the datashare. This identifier is an Amazon Web Services account ID or a keyword, such as ADX.</p>
    pub consumer_identifier: ::std::option::Option<::std::string::String>,
}
impl DeauthorizeDataShareInput {
    /// <p>The namespace Amazon Resource Name (ARN) of the datashare to remove authorization from.</p>
    pub fn data_share_arn(&self) -> ::std::option::Option<&str> {
        self.data_share_arn.as_deref()
    }
    /// <p>The identifier of the data consumer that is to have authorization removed from the datashare. This identifier is an Amazon Web Services account ID or a keyword, such as ADX.</p>
    pub fn consumer_identifier(&self) -> ::std::option::Option<&str> {
        self.consumer_identifier.as_deref()
    }
}
impl DeauthorizeDataShareInput {
    /// Creates a new builder-style object to manufacture [`DeauthorizeDataShareInput`](crate::operation::deauthorize_data_share::DeauthorizeDataShareInput).
    pub fn builder() -> crate::operation::deauthorize_data_share::builders::DeauthorizeDataShareInputBuilder {
        crate::operation::deauthorize_data_share::builders::DeauthorizeDataShareInputBuilder::default()
    }
}

/// A builder for [`DeauthorizeDataShareInput`](crate::operation::deauthorize_data_share::DeauthorizeDataShareInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeauthorizeDataShareInputBuilder {
    pub(crate) data_share_arn: ::std::option::Option<::std::string::String>,
    pub(crate) consumer_identifier: ::std::option::Option<::std::string::String>,
}
impl DeauthorizeDataShareInputBuilder {
    /// <p>The namespace Amazon Resource Name (ARN) of the datashare to remove authorization from.</p>
    /// This field is required.
    pub fn data_share_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_share_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The namespace Amazon Resource Name (ARN) of the datashare to remove authorization from.</p>
    pub fn set_data_share_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_share_arn = input;
        self
    }
    /// <p>The namespace Amazon Resource Name (ARN) of the datashare to remove authorization from.</p>
    pub fn get_data_share_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_share_arn
    }
    /// <p>The identifier of the data consumer that is to have authorization removed from the datashare. This identifier is an Amazon Web Services account ID or a keyword, such as ADX.</p>
    /// This field is required.
    pub fn consumer_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.consumer_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the data consumer that is to have authorization removed from the datashare. This identifier is an Amazon Web Services account ID or a keyword, such as ADX.</p>
    pub fn set_consumer_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.consumer_identifier = input;
        self
    }
    /// <p>The identifier of the data consumer that is to have authorization removed from the datashare. This identifier is an Amazon Web Services account ID or a keyword, such as ADX.</p>
    pub fn get_consumer_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.consumer_identifier
    }
    /// Consumes the builder and constructs a [`DeauthorizeDataShareInput`](crate::operation::deauthorize_data_share::DeauthorizeDataShareInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::deauthorize_data_share::DeauthorizeDataShareInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::deauthorize_data_share::DeauthorizeDataShareInput {
            data_share_arn: self.data_share_arn,
            consumer_identifier: self.consumer_identifier,
        })
    }
}
