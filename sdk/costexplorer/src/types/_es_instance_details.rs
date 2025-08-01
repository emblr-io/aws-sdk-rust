// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the Amazon OpenSearch Service reservations that Amazon Web Services recommends that you purchase.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EsInstanceDetails {
    /// <p>The class of instance that Amazon Web Services recommends.</p>
    pub instance_class: ::std::option::Option<::std::string::String>,
    /// <p>The size of instance that Amazon Web Services recommends.</p>
    pub instance_size: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services Region of the recommended reservation.</p>
    pub region: ::std::option::Option<::std::string::String>,
    /// <p>Determines whether the recommendation is for a current-generation instance.</p>
    pub current_generation: bool,
    /// <p>Determines whether the recommended reservation is size flexible.</p>
    pub size_flex_eligible: bool,
}
impl EsInstanceDetails {
    /// <p>The class of instance that Amazon Web Services recommends.</p>
    pub fn instance_class(&self) -> ::std::option::Option<&str> {
        self.instance_class.as_deref()
    }
    /// <p>The size of instance that Amazon Web Services recommends.</p>
    pub fn instance_size(&self) -> ::std::option::Option<&str> {
        self.instance_size.as_deref()
    }
    /// <p>The Amazon Web Services Region of the recommended reservation.</p>
    pub fn region(&self) -> ::std::option::Option<&str> {
        self.region.as_deref()
    }
    /// <p>Determines whether the recommendation is for a current-generation instance.</p>
    pub fn current_generation(&self) -> bool {
        self.current_generation
    }
    /// <p>Determines whether the recommended reservation is size flexible.</p>
    pub fn size_flex_eligible(&self) -> bool {
        self.size_flex_eligible
    }
}
impl EsInstanceDetails {
    /// Creates a new builder-style object to manufacture [`EsInstanceDetails`](crate::types::EsInstanceDetails).
    pub fn builder() -> crate::types::builders::EsInstanceDetailsBuilder {
        crate::types::builders::EsInstanceDetailsBuilder::default()
    }
}

/// A builder for [`EsInstanceDetails`](crate::types::EsInstanceDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EsInstanceDetailsBuilder {
    pub(crate) instance_class: ::std::option::Option<::std::string::String>,
    pub(crate) instance_size: ::std::option::Option<::std::string::String>,
    pub(crate) region: ::std::option::Option<::std::string::String>,
    pub(crate) current_generation: ::std::option::Option<bool>,
    pub(crate) size_flex_eligible: ::std::option::Option<bool>,
}
impl EsInstanceDetailsBuilder {
    /// <p>The class of instance that Amazon Web Services recommends.</p>
    pub fn instance_class(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_class = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The class of instance that Amazon Web Services recommends.</p>
    pub fn set_instance_class(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_class = input;
        self
    }
    /// <p>The class of instance that Amazon Web Services recommends.</p>
    pub fn get_instance_class(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_class
    }
    /// <p>The size of instance that Amazon Web Services recommends.</p>
    pub fn instance_size(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_size = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The size of instance that Amazon Web Services recommends.</p>
    pub fn set_instance_size(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_size = input;
        self
    }
    /// <p>The size of instance that Amazon Web Services recommends.</p>
    pub fn get_instance_size(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_size
    }
    /// <p>The Amazon Web Services Region of the recommended reservation.</p>
    pub fn region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region of the recommended reservation.</p>
    pub fn set_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region = input;
        self
    }
    /// <p>The Amazon Web Services Region of the recommended reservation.</p>
    pub fn get_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.region
    }
    /// <p>Determines whether the recommendation is for a current-generation instance.</p>
    pub fn current_generation(mut self, input: bool) -> Self {
        self.current_generation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether the recommendation is for a current-generation instance.</p>
    pub fn set_current_generation(mut self, input: ::std::option::Option<bool>) -> Self {
        self.current_generation = input;
        self
    }
    /// <p>Determines whether the recommendation is for a current-generation instance.</p>
    pub fn get_current_generation(&self) -> &::std::option::Option<bool> {
        &self.current_generation
    }
    /// <p>Determines whether the recommended reservation is size flexible.</p>
    pub fn size_flex_eligible(mut self, input: bool) -> Self {
        self.size_flex_eligible = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether the recommended reservation is size flexible.</p>
    pub fn set_size_flex_eligible(mut self, input: ::std::option::Option<bool>) -> Self {
        self.size_flex_eligible = input;
        self
    }
    /// <p>Determines whether the recommended reservation is size flexible.</p>
    pub fn get_size_flex_eligible(&self) -> &::std::option::Option<bool> {
        &self.size_flex_eligible
    }
    /// Consumes the builder and constructs a [`EsInstanceDetails`](crate::types::EsInstanceDetails).
    pub fn build(self) -> crate::types::EsInstanceDetails {
        crate::types::EsInstanceDetails {
            instance_class: self.instance_class,
            instance_size: self.instance_size,
            region: self.region,
            current_generation: self.current_generation.unwrap_or_default(),
            size_flex_eligible: self.size_flex_eligible.unwrap_or_default(),
        }
    }
}
