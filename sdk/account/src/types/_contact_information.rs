// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the details of the primary contact information associated with an Amazon Web Services account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ContactInformation {
    /// <p>The full name of the primary contact address.</p>
    pub full_name: ::std::string::String,
    /// <p>The first line of the primary contact address.</p>
    pub address_line1: ::std::string::String,
    /// <p>The second line of the primary contact address, if any.</p>
    pub address_line2: ::std::option::Option<::std::string::String>,
    /// <p>The third line of the primary contact address, if any.</p>
    pub address_line3: ::std::option::Option<::std::string::String>,
    /// <p>The city of the primary contact address.</p>
    pub city: ::std::string::String,
    /// <p>The state or region of the primary contact address. If the mailing address is within the United States (US), the value in this field can be either a two character state code (for example, <code>NJ</code>) or the full state name (for example, <code>New Jersey</code>). This field is required in the following countries: <code>US</code>, <code>CA</code>, <code>GB</code>, <code>DE</code>, <code>JP</code>, <code>IN</code>, and <code>BR</code>.</p>
    pub state_or_region: ::std::option::Option<::std::string::String>,
    /// <p>The district or county of the primary contact address, if any.</p>
    pub district_or_county: ::std::option::Option<::std::string::String>,
    /// <p>The postal code of the primary contact address.</p>
    pub postal_code: ::std::string::String,
    /// <p>The ISO-3166 two-letter country code for the primary contact address.</p>
    pub country_code: ::std::string::String,
    /// <p>The phone number of the primary contact information. The number will be validated and, in some countries, checked for activation.</p>
    pub phone_number: ::std::string::String,
    /// <p>The name of the company associated with the primary contact information, if any.</p>
    pub company_name: ::std::option::Option<::std::string::String>,
    /// <p>The URL of the website associated with the primary contact information, if any.</p>
    pub website_url: ::std::option::Option<::std::string::String>,
}
impl ContactInformation {
    /// <p>The full name of the primary contact address.</p>
    pub fn full_name(&self) -> &str {
        use std::ops::Deref;
        self.full_name.deref()
    }
    /// <p>The first line of the primary contact address.</p>
    pub fn address_line1(&self) -> &str {
        use std::ops::Deref;
        self.address_line1.deref()
    }
    /// <p>The second line of the primary contact address, if any.</p>
    pub fn address_line2(&self) -> ::std::option::Option<&str> {
        self.address_line2.as_deref()
    }
    /// <p>The third line of the primary contact address, if any.</p>
    pub fn address_line3(&self) -> ::std::option::Option<&str> {
        self.address_line3.as_deref()
    }
    /// <p>The city of the primary contact address.</p>
    pub fn city(&self) -> &str {
        use std::ops::Deref;
        self.city.deref()
    }
    /// <p>The state or region of the primary contact address. If the mailing address is within the United States (US), the value in this field can be either a two character state code (for example, <code>NJ</code>) or the full state name (for example, <code>New Jersey</code>). This field is required in the following countries: <code>US</code>, <code>CA</code>, <code>GB</code>, <code>DE</code>, <code>JP</code>, <code>IN</code>, and <code>BR</code>.</p>
    pub fn state_or_region(&self) -> ::std::option::Option<&str> {
        self.state_or_region.as_deref()
    }
    /// <p>The district or county of the primary contact address, if any.</p>
    pub fn district_or_county(&self) -> ::std::option::Option<&str> {
        self.district_or_county.as_deref()
    }
    /// <p>The postal code of the primary contact address.</p>
    pub fn postal_code(&self) -> &str {
        use std::ops::Deref;
        self.postal_code.deref()
    }
    /// <p>The ISO-3166 two-letter country code for the primary contact address.</p>
    pub fn country_code(&self) -> &str {
        use std::ops::Deref;
        self.country_code.deref()
    }
    /// <p>The phone number of the primary contact information. The number will be validated and, in some countries, checked for activation.</p>
    pub fn phone_number(&self) -> &str {
        use std::ops::Deref;
        self.phone_number.deref()
    }
    /// <p>The name of the company associated with the primary contact information, if any.</p>
    pub fn company_name(&self) -> ::std::option::Option<&str> {
        self.company_name.as_deref()
    }
    /// <p>The URL of the website associated with the primary contact information, if any.</p>
    pub fn website_url(&self) -> ::std::option::Option<&str> {
        self.website_url.as_deref()
    }
}
impl ::std::fmt::Debug for ContactInformation {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ContactInformation");
        formatter.field("full_name", &"*** Sensitive Data Redacted ***");
        formatter.field("address_line1", &"*** Sensitive Data Redacted ***");
        formatter.field("address_line2", &"*** Sensitive Data Redacted ***");
        formatter.field("address_line3", &"*** Sensitive Data Redacted ***");
        formatter.field("city", &"*** Sensitive Data Redacted ***");
        formatter.field("state_or_region", &"*** Sensitive Data Redacted ***");
        formatter.field("district_or_county", &"*** Sensitive Data Redacted ***");
        formatter.field("postal_code", &"*** Sensitive Data Redacted ***");
        formatter.field("country_code", &"*** Sensitive Data Redacted ***");
        formatter.field("phone_number", &"*** Sensitive Data Redacted ***");
        formatter.field("company_name", &"*** Sensitive Data Redacted ***");
        formatter.field("website_url", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl ContactInformation {
    /// Creates a new builder-style object to manufacture [`ContactInformation`](crate::types::ContactInformation).
    pub fn builder() -> crate::types::builders::ContactInformationBuilder {
        crate::types::builders::ContactInformationBuilder::default()
    }
}

/// A builder for [`ContactInformation`](crate::types::ContactInformation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ContactInformationBuilder {
    pub(crate) full_name: ::std::option::Option<::std::string::String>,
    pub(crate) address_line1: ::std::option::Option<::std::string::String>,
    pub(crate) address_line2: ::std::option::Option<::std::string::String>,
    pub(crate) address_line3: ::std::option::Option<::std::string::String>,
    pub(crate) city: ::std::option::Option<::std::string::String>,
    pub(crate) state_or_region: ::std::option::Option<::std::string::String>,
    pub(crate) district_or_county: ::std::option::Option<::std::string::String>,
    pub(crate) postal_code: ::std::option::Option<::std::string::String>,
    pub(crate) country_code: ::std::option::Option<::std::string::String>,
    pub(crate) phone_number: ::std::option::Option<::std::string::String>,
    pub(crate) company_name: ::std::option::Option<::std::string::String>,
    pub(crate) website_url: ::std::option::Option<::std::string::String>,
}
impl ContactInformationBuilder {
    /// <p>The full name of the primary contact address.</p>
    /// This field is required.
    pub fn full_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.full_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The full name of the primary contact address.</p>
    pub fn set_full_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.full_name = input;
        self
    }
    /// <p>The full name of the primary contact address.</p>
    pub fn get_full_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.full_name
    }
    /// <p>The first line of the primary contact address.</p>
    /// This field is required.
    pub fn address_line1(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address_line1 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The first line of the primary contact address.</p>
    pub fn set_address_line1(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address_line1 = input;
        self
    }
    /// <p>The first line of the primary contact address.</p>
    pub fn get_address_line1(&self) -> &::std::option::Option<::std::string::String> {
        &self.address_line1
    }
    /// <p>The second line of the primary contact address, if any.</p>
    pub fn address_line2(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address_line2 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The second line of the primary contact address, if any.</p>
    pub fn set_address_line2(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address_line2 = input;
        self
    }
    /// <p>The second line of the primary contact address, if any.</p>
    pub fn get_address_line2(&self) -> &::std::option::Option<::std::string::String> {
        &self.address_line2
    }
    /// <p>The third line of the primary contact address, if any.</p>
    pub fn address_line3(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.address_line3 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The third line of the primary contact address, if any.</p>
    pub fn set_address_line3(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.address_line3 = input;
        self
    }
    /// <p>The third line of the primary contact address, if any.</p>
    pub fn get_address_line3(&self) -> &::std::option::Option<::std::string::String> {
        &self.address_line3
    }
    /// <p>The city of the primary contact address.</p>
    /// This field is required.
    pub fn city(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.city = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The city of the primary contact address.</p>
    pub fn set_city(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.city = input;
        self
    }
    /// <p>The city of the primary contact address.</p>
    pub fn get_city(&self) -> &::std::option::Option<::std::string::String> {
        &self.city
    }
    /// <p>The state or region of the primary contact address. If the mailing address is within the United States (US), the value in this field can be either a two character state code (for example, <code>NJ</code>) or the full state name (for example, <code>New Jersey</code>). This field is required in the following countries: <code>US</code>, <code>CA</code>, <code>GB</code>, <code>DE</code>, <code>JP</code>, <code>IN</code>, and <code>BR</code>.</p>
    pub fn state_or_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state_or_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The state or region of the primary contact address. If the mailing address is within the United States (US), the value in this field can be either a two character state code (for example, <code>NJ</code>) or the full state name (for example, <code>New Jersey</code>). This field is required in the following countries: <code>US</code>, <code>CA</code>, <code>GB</code>, <code>DE</code>, <code>JP</code>, <code>IN</code>, and <code>BR</code>.</p>
    pub fn set_state_or_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state_or_region = input;
        self
    }
    /// <p>The state or region of the primary contact address. If the mailing address is within the United States (US), the value in this field can be either a two character state code (for example, <code>NJ</code>) or the full state name (for example, <code>New Jersey</code>). This field is required in the following countries: <code>US</code>, <code>CA</code>, <code>GB</code>, <code>DE</code>, <code>JP</code>, <code>IN</code>, and <code>BR</code>.</p>
    pub fn get_state_or_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.state_or_region
    }
    /// <p>The district or county of the primary contact address, if any.</p>
    pub fn district_or_county(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.district_or_county = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The district or county of the primary contact address, if any.</p>
    pub fn set_district_or_county(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.district_or_county = input;
        self
    }
    /// <p>The district or county of the primary contact address, if any.</p>
    pub fn get_district_or_county(&self) -> &::std::option::Option<::std::string::String> {
        &self.district_or_county
    }
    /// <p>The postal code of the primary contact address.</p>
    /// This field is required.
    pub fn postal_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.postal_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The postal code of the primary contact address.</p>
    pub fn set_postal_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.postal_code = input;
        self
    }
    /// <p>The postal code of the primary contact address.</p>
    pub fn get_postal_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.postal_code
    }
    /// <p>The ISO-3166 two-letter country code for the primary contact address.</p>
    /// This field is required.
    pub fn country_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.country_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ISO-3166 two-letter country code for the primary contact address.</p>
    pub fn set_country_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.country_code = input;
        self
    }
    /// <p>The ISO-3166 two-letter country code for the primary contact address.</p>
    pub fn get_country_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.country_code
    }
    /// <p>The phone number of the primary contact information. The number will be validated and, in some countries, checked for activation.</p>
    /// This field is required.
    pub fn phone_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.phone_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The phone number of the primary contact information. The number will be validated and, in some countries, checked for activation.</p>
    pub fn set_phone_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.phone_number = input;
        self
    }
    /// <p>The phone number of the primary contact information. The number will be validated and, in some countries, checked for activation.</p>
    pub fn get_phone_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.phone_number
    }
    /// <p>The name of the company associated with the primary contact information, if any.</p>
    pub fn company_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.company_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the company associated with the primary contact information, if any.</p>
    pub fn set_company_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.company_name = input;
        self
    }
    /// <p>The name of the company associated with the primary contact information, if any.</p>
    pub fn get_company_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.company_name
    }
    /// <p>The URL of the website associated with the primary contact information, if any.</p>
    pub fn website_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.website_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the website associated with the primary contact information, if any.</p>
    pub fn set_website_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.website_url = input;
        self
    }
    /// <p>The URL of the website associated with the primary contact information, if any.</p>
    pub fn get_website_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.website_url
    }
    /// Consumes the builder and constructs a [`ContactInformation`](crate::types::ContactInformation).
    /// This method will fail if any of the following fields are not set:
    /// - [`full_name`](crate::types::builders::ContactInformationBuilder::full_name)
    /// - [`address_line1`](crate::types::builders::ContactInformationBuilder::address_line1)
    /// - [`city`](crate::types::builders::ContactInformationBuilder::city)
    /// - [`postal_code`](crate::types::builders::ContactInformationBuilder::postal_code)
    /// - [`country_code`](crate::types::builders::ContactInformationBuilder::country_code)
    /// - [`phone_number`](crate::types::builders::ContactInformationBuilder::phone_number)
    pub fn build(self) -> ::std::result::Result<crate::types::ContactInformation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ContactInformation {
            full_name: self.full_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "full_name",
                    "full_name was not specified but it is required when building ContactInformation",
                )
            })?,
            address_line1: self.address_line1.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "address_line1",
                    "address_line1 was not specified but it is required when building ContactInformation",
                )
            })?,
            address_line2: self.address_line2,
            address_line3: self.address_line3,
            city: self.city.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "city",
                    "city was not specified but it is required when building ContactInformation",
                )
            })?,
            state_or_region: self.state_or_region,
            district_or_county: self.district_or_county,
            postal_code: self.postal_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "postal_code",
                    "postal_code was not specified but it is required when building ContactInformation",
                )
            })?,
            country_code: self.country_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "country_code",
                    "country_code was not specified but it is required when building ContactInformation",
                )
            })?,
            phone_number: self.phone_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "phone_number",
                    "phone_number was not specified but it is required when building ContactInformation",
                )
            })?,
            company_name: self.company_name,
            website_url: self.website_url,
        })
    }
}
impl ::std::fmt::Debug for ContactInformationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ContactInformationBuilder");
        formatter.field("full_name", &"*** Sensitive Data Redacted ***");
        formatter.field("address_line1", &"*** Sensitive Data Redacted ***");
        formatter.field("address_line2", &"*** Sensitive Data Redacted ***");
        formatter.field("address_line3", &"*** Sensitive Data Redacted ***");
        formatter.field("city", &"*** Sensitive Data Redacted ***");
        formatter.field("state_or_region", &"*** Sensitive Data Redacted ***");
        formatter.field("district_or_county", &"*** Sensitive Data Redacted ***");
        formatter.field("postal_code", &"*** Sensitive Data Redacted ***");
        formatter.field("country_code", &"*** Sensitive Data Redacted ***");
        formatter.field("phone_number", &"*** Sensitive Data Redacted ***");
        formatter.field("company_name", &"*** Sensitive Data Redacted ***");
        formatter.field("website_url", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
