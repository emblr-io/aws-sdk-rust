// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An array that contains the sensitivity parameters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DifferentialPrivacyParameters {
    /// <p>Provides the sensitivity parameters that you can use to better understand the total amount of noise in query results.</p>
    pub sensitivity_parameters: ::std::vec::Vec<crate::types::DifferentialPrivacySensitivityParameters>,
}
impl DifferentialPrivacyParameters {
    /// <p>Provides the sensitivity parameters that you can use to better understand the total amount of noise in query results.</p>
    pub fn sensitivity_parameters(&self) -> &[crate::types::DifferentialPrivacySensitivityParameters] {
        use std::ops::Deref;
        self.sensitivity_parameters.deref()
    }
}
impl DifferentialPrivacyParameters {
    /// Creates a new builder-style object to manufacture [`DifferentialPrivacyParameters`](crate::types::DifferentialPrivacyParameters).
    pub fn builder() -> crate::types::builders::DifferentialPrivacyParametersBuilder {
        crate::types::builders::DifferentialPrivacyParametersBuilder::default()
    }
}

/// A builder for [`DifferentialPrivacyParameters`](crate::types::DifferentialPrivacyParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DifferentialPrivacyParametersBuilder {
    pub(crate) sensitivity_parameters: ::std::option::Option<::std::vec::Vec<crate::types::DifferentialPrivacySensitivityParameters>>,
}
impl DifferentialPrivacyParametersBuilder {
    /// Appends an item to `sensitivity_parameters`.
    ///
    /// To override the contents of this collection use [`set_sensitivity_parameters`](Self::set_sensitivity_parameters).
    ///
    /// <p>Provides the sensitivity parameters that you can use to better understand the total amount of noise in query results.</p>
    pub fn sensitivity_parameters(mut self, input: crate::types::DifferentialPrivacySensitivityParameters) -> Self {
        let mut v = self.sensitivity_parameters.unwrap_or_default();
        v.push(input);
        self.sensitivity_parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Provides the sensitivity parameters that you can use to better understand the total amount of noise in query results.</p>
    pub fn set_sensitivity_parameters(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DifferentialPrivacySensitivityParameters>>,
    ) -> Self {
        self.sensitivity_parameters = input;
        self
    }
    /// <p>Provides the sensitivity parameters that you can use to better understand the total amount of noise in query results.</p>
    pub fn get_sensitivity_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DifferentialPrivacySensitivityParameters>> {
        &self.sensitivity_parameters
    }
    /// Consumes the builder and constructs a [`DifferentialPrivacyParameters`](crate::types::DifferentialPrivacyParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`sensitivity_parameters`](crate::types::builders::DifferentialPrivacyParametersBuilder::sensitivity_parameters)
    pub fn build(self) -> ::std::result::Result<crate::types::DifferentialPrivacyParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DifferentialPrivacyParameters {
            sensitivity_parameters: self.sensitivity_parameters.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sensitivity_parameters",
                    "sensitivity_parameters was not specified but it is required when building DifferentialPrivacyParameters",
                )
            })?,
        })
    }
}
