// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The epsilon and noise parameters that you want to preview.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DifferentialPrivacyPreviewParametersInput {
    /// <p>The epsilon value that you want to preview.</p>
    pub epsilon: i32,
    /// <p>Noise added per query is measured in terms of the number of users whose contributions you want to obscure. This value governs the rate at which the privacy budget is depleted.</p>
    pub users_noise_per_query: i32,
}
impl DifferentialPrivacyPreviewParametersInput {
    /// <p>The epsilon value that you want to preview.</p>
    pub fn epsilon(&self) -> i32 {
        self.epsilon
    }
    /// <p>Noise added per query is measured in terms of the number of users whose contributions you want to obscure. This value governs the rate at which the privacy budget is depleted.</p>
    pub fn users_noise_per_query(&self) -> i32 {
        self.users_noise_per_query
    }
}
impl DifferentialPrivacyPreviewParametersInput {
    /// Creates a new builder-style object to manufacture [`DifferentialPrivacyPreviewParametersInput`](crate::types::DifferentialPrivacyPreviewParametersInput).
    pub fn builder() -> crate::types::builders::DifferentialPrivacyPreviewParametersInputBuilder {
        crate::types::builders::DifferentialPrivacyPreviewParametersInputBuilder::default()
    }
}

/// A builder for [`DifferentialPrivacyPreviewParametersInput`](crate::types::DifferentialPrivacyPreviewParametersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DifferentialPrivacyPreviewParametersInputBuilder {
    pub(crate) epsilon: ::std::option::Option<i32>,
    pub(crate) users_noise_per_query: ::std::option::Option<i32>,
}
impl DifferentialPrivacyPreviewParametersInputBuilder {
    /// <p>The epsilon value that you want to preview.</p>
    /// This field is required.
    pub fn epsilon(mut self, input: i32) -> Self {
        self.epsilon = ::std::option::Option::Some(input);
        self
    }
    /// <p>The epsilon value that you want to preview.</p>
    pub fn set_epsilon(mut self, input: ::std::option::Option<i32>) -> Self {
        self.epsilon = input;
        self
    }
    /// <p>The epsilon value that you want to preview.</p>
    pub fn get_epsilon(&self) -> &::std::option::Option<i32> {
        &self.epsilon
    }
    /// <p>Noise added per query is measured in terms of the number of users whose contributions you want to obscure. This value governs the rate at which the privacy budget is depleted.</p>
    /// This field is required.
    pub fn users_noise_per_query(mut self, input: i32) -> Self {
        self.users_noise_per_query = ::std::option::Option::Some(input);
        self
    }
    /// <p>Noise added per query is measured in terms of the number of users whose contributions you want to obscure. This value governs the rate at which the privacy budget is depleted.</p>
    pub fn set_users_noise_per_query(mut self, input: ::std::option::Option<i32>) -> Self {
        self.users_noise_per_query = input;
        self
    }
    /// <p>Noise added per query is measured in terms of the number of users whose contributions you want to obscure. This value governs the rate at which the privacy budget is depleted.</p>
    pub fn get_users_noise_per_query(&self) -> &::std::option::Option<i32> {
        &self.users_noise_per_query
    }
    /// Consumes the builder and constructs a [`DifferentialPrivacyPreviewParametersInput`](crate::types::DifferentialPrivacyPreviewParametersInput).
    /// This method will fail if any of the following fields are not set:
    /// - [`epsilon`](crate::types::builders::DifferentialPrivacyPreviewParametersInputBuilder::epsilon)
    /// - [`users_noise_per_query`](crate::types::builders::DifferentialPrivacyPreviewParametersInputBuilder::users_noise_per_query)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::DifferentialPrivacyPreviewParametersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DifferentialPrivacyPreviewParametersInput {
            epsilon: self.epsilon.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "epsilon",
                    "epsilon was not specified but it is required when building DifferentialPrivacyPreviewParametersInput",
                )
            })?,
            users_noise_per_query: self.users_noise_per_query.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "users_noise_per_query",
                    "users_noise_per_query was not specified but it is required when building DifferentialPrivacyPreviewParametersInput",
                )
            })?,
        })
    }
}
