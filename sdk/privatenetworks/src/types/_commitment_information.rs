// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Shows the duration, the date and time that the contract started and ends, and the renewal status of the commitment period for the radio unit.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CommitmentInformation {
    /// <p>The duration and renewal status of the commitment period for the radio unit.</p>
    pub commitment_configuration: ::std::option::Option<crate::types::CommitmentConfiguration>,
    /// <p>The date and time that the commitment period started.</p>
    pub start_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the commitment period ends. If you do not cancel or renew the commitment before the expiration date, you will be billed at the 60-day-commitment rate.</p>
    pub expires_on: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl CommitmentInformation {
    /// <p>The duration and renewal status of the commitment period for the radio unit.</p>
    pub fn commitment_configuration(&self) -> ::std::option::Option<&crate::types::CommitmentConfiguration> {
        self.commitment_configuration.as_ref()
    }
    /// <p>The date and time that the commitment period started.</p>
    pub fn start_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_at.as_ref()
    }
    /// <p>The date and time that the commitment period ends. If you do not cancel or renew the commitment before the expiration date, you will be billed at the 60-day-commitment rate.</p>
    pub fn expires_on(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.expires_on.as_ref()
    }
}
impl CommitmentInformation {
    /// Creates a new builder-style object to manufacture [`CommitmentInformation`](crate::types::CommitmentInformation).
    pub fn builder() -> crate::types::builders::CommitmentInformationBuilder {
        crate::types::builders::CommitmentInformationBuilder::default()
    }
}

/// A builder for [`CommitmentInformation`](crate::types::CommitmentInformation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CommitmentInformationBuilder {
    pub(crate) commitment_configuration: ::std::option::Option<crate::types::CommitmentConfiguration>,
    pub(crate) start_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) expires_on: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl CommitmentInformationBuilder {
    /// <p>The duration and renewal status of the commitment period for the radio unit.</p>
    /// This field is required.
    pub fn commitment_configuration(mut self, input: crate::types::CommitmentConfiguration) -> Self {
        self.commitment_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The duration and renewal status of the commitment period for the radio unit.</p>
    pub fn set_commitment_configuration(mut self, input: ::std::option::Option<crate::types::CommitmentConfiguration>) -> Self {
        self.commitment_configuration = input;
        self
    }
    /// <p>The duration and renewal status of the commitment period for the radio unit.</p>
    pub fn get_commitment_configuration(&self) -> &::std::option::Option<crate::types::CommitmentConfiguration> {
        &self.commitment_configuration
    }
    /// <p>The date and time that the commitment period started.</p>
    pub fn start_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the commitment period started.</p>
    pub fn set_start_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_at = input;
        self
    }
    /// <p>The date and time that the commitment period started.</p>
    pub fn get_start_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_at
    }
    /// <p>The date and time that the commitment period ends. If you do not cancel or renew the commitment before the expiration date, you will be billed at the 60-day-commitment rate.</p>
    pub fn expires_on(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.expires_on = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the commitment period ends. If you do not cancel or renew the commitment before the expiration date, you will be billed at the 60-day-commitment rate.</p>
    pub fn set_expires_on(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.expires_on = input;
        self
    }
    /// <p>The date and time that the commitment period ends. If you do not cancel or renew the commitment before the expiration date, you will be billed at the 60-day-commitment rate.</p>
    pub fn get_expires_on(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.expires_on
    }
    /// Consumes the builder and constructs a [`CommitmentInformation`](crate::types::CommitmentInformation).
    pub fn build(self) -> crate::types::CommitmentInformation {
        crate::types::CommitmentInformation {
            commitment_configuration: self.commitment_configuration,
            start_at: self.start_at,
            expires_on: self.expires_on,
        }
    }
}
