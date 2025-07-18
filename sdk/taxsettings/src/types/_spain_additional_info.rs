// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Additional tax information associated with your TRN in Spain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SpainAdditionalInfo {
    /// <p>The registration type in Spain.</p>
    pub registration_type: crate::types::RegistrationType,
}
impl SpainAdditionalInfo {
    /// <p>The registration type in Spain.</p>
    pub fn registration_type(&self) -> &crate::types::RegistrationType {
        &self.registration_type
    }
}
impl SpainAdditionalInfo {
    /// Creates a new builder-style object to manufacture [`SpainAdditionalInfo`](crate::types::SpainAdditionalInfo).
    pub fn builder() -> crate::types::builders::SpainAdditionalInfoBuilder {
        crate::types::builders::SpainAdditionalInfoBuilder::default()
    }
}

/// A builder for [`SpainAdditionalInfo`](crate::types::SpainAdditionalInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SpainAdditionalInfoBuilder {
    pub(crate) registration_type: ::std::option::Option<crate::types::RegistrationType>,
}
impl SpainAdditionalInfoBuilder {
    /// <p>The registration type in Spain.</p>
    /// This field is required.
    pub fn registration_type(mut self, input: crate::types::RegistrationType) -> Self {
        self.registration_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The registration type in Spain.</p>
    pub fn set_registration_type(mut self, input: ::std::option::Option<crate::types::RegistrationType>) -> Self {
        self.registration_type = input;
        self
    }
    /// <p>The registration type in Spain.</p>
    pub fn get_registration_type(&self) -> &::std::option::Option<crate::types::RegistrationType> {
        &self.registration_type
    }
    /// Consumes the builder and constructs a [`SpainAdditionalInfo`](crate::types::SpainAdditionalInfo).
    /// This method will fail if any of the following fields are not set:
    /// - [`registration_type`](crate::types::builders::SpainAdditionalInfoBuilder::registration_type)
    pub fn build(self) -> ::std::result::Result<crate::types::SpainAdditionalInfo, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SpainAdditionalInfo {
            registration_type: self.registration_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "registration_type",
                    "registration_type was not specified but it is required when building SpainAdditionalInfo",
                )
            })?,
        })
    }
}
