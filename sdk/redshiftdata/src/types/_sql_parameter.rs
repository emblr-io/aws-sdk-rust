// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A parameter used in a SQL statement.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SqlParameter {
    /// <p>The name of the parameter.</p>
    pub name: ::std::string::String,
    /// <p>The value of the parameter. Amazon Redshift implicitly converts to the proper data type. For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/c_Supported_data_types.html">Data types</a> in the <i>Amazon Redshift Database Developer Guide</i>.</p>
    pub value: ::std::string::String,
}
impl SqlParameter {
    /// <p>The name of the parameter.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The value of the parameter. Amazon Redshift implicitly converts to the proper data type. For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/c_Supported_data_types.html">Data types</a> in the <i>Amazon Redshift Database Developer Guide</i>.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl SqlParameter {
    /// Creates a new builder-style object to manufacture [`SqlParameter`](crate::types::SqlParameter).
    pub fn builder() -> crate::types::builders::SqlParameterBuilder {
        crate::types::builders::SqlParameterBuilder::default()
    }
}

/// A builder for [`SqlParameter`](crate::types::SqlParameter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SqlParameterBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl SqlParameterBuilder {
    /// <p>The name of the parameter.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the parameter.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the parameter.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The value of the parameter. Amazon Redshift implicitly converts to the proper data type. For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/c_Supported_data_types.html">Data types</a> in the <i>Amazon Redshift Database Developer Guide</i>.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the parameter. Amazon Redshift implicitly converts to the proper data type. For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/c_Supported_data_types.html">Data types</a> in the <i>Amazon Redshift Database Developer Guide</i>.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the parameter. Amazon Redshift implicitly converts to the proper data type. For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/c_Supported_data_types.html">Data types</a> in the <i>Amazon Redshift Database Developer Guide</i>.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`SqlParameter`](crate::types::SqlParameter).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::SqlParameterBuilder::name)
    /// - [`value`](crate::types::builders::SqlParameterBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::SqlParameter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SqlParameter {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building SqlParameter",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building SqlParameter",
                )
            })?,
        })
    }
}
