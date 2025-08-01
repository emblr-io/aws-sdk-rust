// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the unique identifier for your users.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DifferentialPrivacyConfiguration {
    /// <p>The name of the column (such as user_id) that contains the unique identifier of your users whose privacy you want to protect. If you want to turn on diﬀerential privacy for two or more tables in a collaboration, you must conﬁgure the same column as the user identiﬁer column in both analysis rules.</p>
    pub columns: ::std::vec::Vec<crate::types::DifferentialPrivacyColumn>,
}
impl DifferentialPrivacyConfiguration {
    /// <p>The name of the column (such as user_id) that contains the unique identifier of your users whose privacy you want to protect. If you want to turn on diﬀerential privacy for two or more tables in a collaboration, you must conﬁgure the same column as the user identiﬁer column in both analysis rules.</p>
    pub fn columns(&self) -> &[crate::types::DifferentialPrivacyColumn] {
        use std::ops::Deref;
        self.columns.deref()
    }
}
impl DifferentialPrivacyConfiguration {
    /// Creates a new builder-style object to manufacture [`DifferentialPrivacyConfiguration`](crate::types::DifferentialPrivacyConfiguration).
    pub fn builder() -> crate::types::builders::DifferentialPrivacyConfigurationBuilder {
        crate::types::builders::DifferentialPrivacyConfigurationBuilder::default()
    }
}

/// A builder for [`DifferentialPrivacyConfiguration`](crate::types::DifferentialPrivacyConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DifferentialPrivacyConfigurationBuilder {
    pub(crate) columns: ::std::option::Option<::std::vec::Vec<crate::types::DifferentialPrivacyColumn>>,
}
impl DifferentialPrivacyConfigurationBuilder {
    /// Appends an item to `columns`.
    ///
    /// To override the contents of this collection use [`set_columns`](Self::set_columns).
    ///
    /// <p>The name of the column (such as user_id) that contains the unique identifier of your users whose privacy you want to protect. If you want to turn on diﬀerential privacy for two or more tables in a collaboration, you must conﬁgure the same column as the user identiﬁer column in both analysis rules.</p>
    pub fn columns(mut self, input: crate::types::DifferentialPrivacyColumn) -> Self {
        let mut v = self.columns.unwrap_or_default();
        v.push(input);
        self.columns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The name of the column (such as user_id) that contains the unique identifier of your users whose privacy you want to protect. If you want to turn on diﬀerential privacy for two or more tables in a collaboration, you must conﬁgure the same column as the user identiﬁer column in both analysis rules.</p>
    pub fn set_columns(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DifferentialPrivacyColumn>>) -> Self {
        self.columns = input;
        self
    }
    /// <p>The name of the column (such as user_id) that contains the unique identifier of your users whose privacy you want to protect. If you want to turn on diﬀerential privacy for two or more tables in a collaboration, you must conﬁgure the same column as the user identiﬁer column in both analysis rules.</p>
    pub fn get_columns(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DifferentialPrivacyColumn>> {
        &self.columns
    }
    /// Consumes the builder and constructs a [`DifferentialPrivacyConfiguration`](crate::types::DifferentialPrivacyConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`columns`](crate::types::builders::DifferentialPrivacyConfigurationBuilder::columns)
    pub fn build(self) -> ::std::result::Result<crate::types::DifferentialPrivacyConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DifferentialPrivacyConfiguration {
            columns: self.columns.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "columns",
                    "columns was not specified but it is required when building DifferentialPrivacyConfiguration",
                )
            })?,
        })
    }
}
