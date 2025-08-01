// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a site.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Site {
    /// <p>The ID of the site.</p>
    pub site_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon Web Services account.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the site.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the site.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The site tags.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) of the site.</p>
    pub site_arn: ::std::option::Option<::std::string::String>,
    /// <p>Notes about a site.</p>
    pub notes: ::std::option::Option<::std::string::String>,
    /// <p>The ISO-3166 two-letter country code where the hardware is installed and powered on.</p>
    pub operating_address_country_code: ::std::option::Option<::std::string::String>,
    /// <p>State or region where the hardware is installed and powered on.</p>
    pub operating_address_state_or_region: ::std::option::Option<::std::string::String>,
    /// <p>City where the hardware is installed and powered on.</p>
    pub operating_address_city: ::std::option::Option<::std::string::String>,
    /// <p>Information about the physical and logistical details for a rack at the site.</p>
    pub rack_physical_properties: ::std::option::Option<crate::types::RackPhysicalProperties>,
}
impl Site {
    /// <p>The ID of the site.</p>
    pub fn site_id(&self) -> ::std::option::Option<&str> {
        self.site_id.as_deref()
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The name of the site.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the site.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The site tags.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the site.</p>
    pub fn site_arn(&self) -> ::std::option::Option<&str> {
        self.site_arn.as_deref()
    }
    /// <p>Notes about a site.</p>
    pub fn notes(&self) -> ::std::option::Option<&str> {
        self.notes.as_deref()
    }
    /// <p>The ISO-3166 two-letter country code where the hardware is installed and powered on.</p>
    pub fn operating_address_country_code(&self) -> ::std::option::Option<&str> {
        self.operating_address_country_code.as_deref()
    }
    /// <p>State or region where the hardware is installed and powered on.</p>
    pub fn operating_address_state_or_region(&self) -> ::std::option::Option<&str> {
        self.operating_address_state_or_region.as_deref()
    }
    /// <p>City where the hardware is installed and powered on.</p>
    pub fn operating_address_city(&self) -> ::std::option::Option<&str> {
        self.operating_address_city.as_deref()
    }
    /// <p>Information about the physical and logistical details for a rack at the site.</p>
    pub fn rack_physical_properties(&self) -> ::std::option::Option<&crate::types::RackPhysicalProperties> {
        self.rack_physical_properties.as_ref()
    }
}
impl Site {
    /// Creates a new builder-style object to manufacture [`Site`](crate::types::Site).
    pub fn builder() -> crate::types::builders::SiteBuilder {
        crate::types::builders::SiteBuilder::default()
    }
}

/// A builder for [`Site`](crate::types::Site).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SiteBuilder {
    pub(crate) site_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) site_arn: ::std::option::Option<::std::string::String>,
    pub(crate) notes: ::std::option::Option<::std::string::String>,
    pub(crate) operating_address_country_code: ::std::option::Option<::std::string::String>,
    pub(crate) operating_address_state_or_region: ::std::option::Option<::std::string::String>,
    pub(crate) operating_address_city: ::std::option::Option<::std::string::String>,
    pub(crate) rack_physical_properties: ::std::option::Option<crate::types::RackPhysicalProperties>,
}
impl SiteBuilder {
    /// <p>The ID of the site.</p>
    pub fn site_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.site_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the site.</p>
    pub fn set_site_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.site_id = input;
        self
    }
    /// <p>The ID of the site.</p>
    pub fn get_site_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.site_id
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The name of the site.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the site.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the site.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the site.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the site.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the site.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The site tags.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The site tags.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The site tags.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The Amazon Resource Name (ARN) of the site.</p>
    pub fn site_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.site_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the site.</p>
    pub fn set_site_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.site_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the site.</p>
    pub fn get_site_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.site_arn
    }
    /// <p>Notes about a site.</p>
    pub fn notes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notes = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Notes about a site.</p>
    pub fn set_notes(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notes = input;
        self
    }
    /// <p>Notes about a site.</p>
    pub fn get_notes(&self) -> &::std::option::Option<::std::string::String> {
        &self.notes
    }
    /// <p>The ISO-3166 two-letter country code where the hardware is installed and powered on.</p>
    pub fn operating_address_country_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operating_address_country_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ISO-3166 two-letter country code where the hardware is installed and powered on.</p>
    pub fn set_operating_address_country_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operating_address_country_code = input;
        self
    }
    /// <p>The ISO-3166 two-letter country code where the hardware is installed and powered on.</p>
    pub fn get_operating_address_country_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.operating_address_country_code
    }
    /// <p>State or region where the hardware is installed and powered on.</p>
    pub fn operating_address_state_or_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operating_address_state_or_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>State or region where the hardware is installed and powered on.</p>
    pub fn set_operating_address_state_or_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operating_address_state_or_region = input;
        self
    }
    /// <p>State or region where the hardware is installed and powered on.</p>
    pub fn get_operating_address_state_or_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.operating_address_state_or_region
    }
    /// <p>City where the hardware is installed and powered on.</p>
    pub fn operating_address_city(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operating_address_city = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>City where the hardware is installed and powered on.</p>
    pub fn set_operating_address_city(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operating_address_city = input;
        self
    }
    /// <p>City where the hardware is installed and powered on.</p>
    pub fn get_operating_address_city(&self) -> &::std::option::Option<::std::string::String> {
        &self.operating_address_city
    }
    /// <p>Information about the physical and logistical details for a rack at the site.</p>
    pub fn rack_physical_properties(mut self, input: crate::types::RackPhysicalProperties) -> Self {
        self.rack_physical_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the physical and logistical details for a rack at the site.</p>
    pub fn set_rack_physical_properties(mut self, input: ::std::option::Option<crate::types::RackPhysicalProperties>) -> Self {
        self.rack_physical_properties = input;
        self
    }
    /// <p>Information about the physical and logistical details for a rack at the site.</p>
    pub fn get_rack_physical_properties(&self) -> &::std::option::Option<crate::types::RackPhysicalProperties> {
        &self.rack_physical_properties
    }
    /// Consumes the builder and constructs a [`Site`](crate::types::Site).
    pub fn build(self) -> crate::types::Site {
        crate::types::Site {
            site_id: self.site_id,
            account_id: self.account_id,
            name: self.name,
            description: self.description,
            tags: self.tags,
            site_arn: self.site_arn,
            notes: self.notes,
            operating_address_country_code: self.operating_address_country_code,
            operating_address_state_or_region: self.operating_address_state_or_region,
            operating_address_city: self.operating_address_city,
            rack_physical_properties: self.rack_physical_properties,
        }
    }
}
