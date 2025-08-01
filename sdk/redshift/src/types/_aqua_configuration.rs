// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The operation that uses this structure is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AquaConfiguration {
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub aqua_status: ::std::option::Option<crate::types::AquaStatus>,
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub aqua_configuration_status: ::std::option::Option<crate::types::AquaConfigurationStatus>,
}
impl AquaConfiguration {
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub fn aqua_status(&self) -> ::std::option::Option<&crate::types::AquaStatus> {
        self.aqua_status.as_ref()
    }
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub fn aqua_configuration_status(&self) -> ::std::option::Option<&crate::types::AquaConfigurationStatus> {
        self.aqua_configuration_status.as_ref()
    }
}
impl AquaConfiguration {
    /// Creates a new builder-style object to manufacture [`AquaConfiguration`](crate::types::AquaConfiguration).
    pub fn builder() -> crate::types::builders::AquaConfigurationBuilder {
        crate::types::builders::AquaConfigurationBuilder::default()
    }
}

/// A builder for [`AquaConfiguration`](crate::types::AquaConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AquaConfigurationBuilder {
    pub(crate) aqua_status: ::std::option::Option<crate::types::AquaStatus>,
    pub(crate) aqua_configuration_status: ::std::option::Option<crate::types::AquaConfigurationStatus>,
}
impl AquaConfigurationBuilder {
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub fn aqua_status(mut self, input: crate::types::AquaStatus) -> Self {
        self.aqua_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub fn set_aqua_status(mut self, input: ::std::option::Option<crate::types::AquaStatus>) -> Self {
        self.aqua_status = input;
        self
    }
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub fn get_aqua_status(&self) -> &::std::option::Option<crate::types::AquaStatus> {
        &self.aqua_status
    }
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub fn aqua_configuration_status(mut self, input: crate::types::AquaConfigurationStatus) -> Self {
        self.aqua_configuration_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub fn set_aqua_configuration_status(mut self, input: ::std::option::Option<crate::types::AquaConfigurationStatus>) -> Self {
        self.aqua_configuration_status = input;
        self
    }
    /// <p>This field is retired. Amazon Redshift automatically determines whether to use AQUA (Advanced Query Accelerator).</p>
    pub fn get_aqua_configuration_status(&self) -> &::std::option::Option<crate::types::AquaConfigurationStatus> {
        &self.aqua_configuration_status
    }
    /// Consumes the builder and constructs a [`AquaConfiguration`](crate::types::AquaConfiguration).
    pub fn build(self) -> crate::types::AquaConfiguration {
        crate::types::AquaConfiguration {
            aqua_status: self.aqua_status,
            aqua_configuration_status: self.aqua_configuration_status,
        }
    }
}
