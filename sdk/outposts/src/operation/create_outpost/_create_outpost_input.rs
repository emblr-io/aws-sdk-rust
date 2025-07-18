// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateOutpostInput {
    /// <p>The name of the Outpost.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the Outpost.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ID or the Amazon Resource Name (ARN) of the site.</p>
    pub site_id: ::std::option::Option<::std::string::String>,
    /// <p>The Availability Zone.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Availability Zone.</p>
    pub availability_zone_id: ::std::option::Option<::std::string::String>,
    /// <p>The tags to apply to the Outpost.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The type of hardware for this Outpost.</p>
    pub supported_hardware_type: ::std::option::Option<crate::types::SupportedHardwareType>,
}
impl CreateOutpostInput {
    /// <p>The name of the Outpost.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the Outpost.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ID or the Amazon Resource Name (ARN) of the site.</p>
    pub fn site_id(&self) -> ::std::option::Option<&str> {
        self.site_id.as_deref()
    }
    /// <p>The Availability Zone.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>The ID of the Availability Zone.</p>
    pub fn availability_zone_id(&self) -> ::std::option::Option<&str> {
        self.availability_zone_id.as_deref()
    }
    /// <p>The tags to apply to the Outpost.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The type of hardware for this Outpost.</p>
    pub fn supported_hardware_type(&self) -> ::std::option::Option<&crate::types::SupportedHardwareType> {
        self.supported_hardware_type.as_ref()
    }
}
impl CreateOutpostInput {
    /// Creates a new builder-style object to manufacture [`CreateOutpostInput`](crate::operation::create_outpost::CreateOutpostInput).
    pub fn builder() -> crate::operation::create_outpost::builders::CreateOutpostInputBuilder {
        crate::operation::create_outpost::builders::CreateOutpostInputBuilder::default()
    }
}

/// A builder for [`CreateOutpostInput`](crate::operation::create_outpost::CreateOutpostInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateOutpostInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) site_id: ::std::option::Option<::std::string::String>,
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) availability_zone_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) supported_hardware_type: ::std::option::Option<crate::types::SupportedHardwareType>,
}
impl CreateOutpostInputBuilder {
    /// <p>The name of the Outpost.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Outpost.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the Outpost.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the Outpost.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the Outpost.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the Outpost.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The ID or the Amazon Resource Name (ARN) of the site.</p>
    /// This field is required.
    pub fn site_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.site_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID or the Amazon Resource Name (ARN) of the site.</p>
    pub fn set_site_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.site_id = input;
        self
    }
    /// <p>The ID or the Amazon Resource Name (ARN) of the site.</p>
    pub fn get_site_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.site_id
    }
    /// <p>The Availability Zone.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Availability Zone.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The Availability Zone.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>The ID of the Availability Zone.</p>
    pub fn availability_zone_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Availability Zone.</p>
    pub fn set_availability_zone_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone_id = input;
        self
    }
    /// <p>The ID of the Availability Zone.</p>
    pub fn get_availability_zone_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone_id
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to apply to the Outpost.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to apply to the Outpost.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to apply to the Outpost.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The type of hardware for this Outpost.</p>
    pub fn supported_hardware_type(mut self, input: crate::types::SupportedHardwareType) -> Self {
        self.supported_hardware_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of hardware for this Outpost.</p>
    pub fn set_supported_hardware_type(mut self, input: ::std::option::Option<crate::types::SupportedHardwareType>) -> Self {
        self.supported_hardware_type = input;
        self
    }
    /// <p>The type of hardware for this Outpost.</p>
    pub fn get_supported_hardware_type(&self) -> &::std::option::Option<crate::types::SupportedHardwareType> {
        &self.supported_hardware_type
    }
    /// Consumes the builder and constructs a [`CreateOutpostInput`](crate::operation::create_outpost::CreateOutpostInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_outpost::CreateOutpostInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_outpost::CreateOutpostInput {
            name: self.name,
            description: self.description,
            site_id: self.site_id,
            availability_zone: self.availability_zone,
            availability_zone_id: self.availability_zone_id,
            tags: self.tags,
            supported_hardware_type: self.supported_hardware_type,
        })
    }
}
