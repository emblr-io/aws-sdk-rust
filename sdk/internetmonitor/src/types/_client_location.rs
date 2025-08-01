// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The impacted location, such as a city, that Amazon Web Services clients access application resources from.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClientLocation {
    /// <p>The name of the internet service provider (ISP) or network (ASN).</p>
    pub as_name: ::std::string::String,
    /// <p>The Autonomous System Number (ASN) of the network at an impacted location.</p>
    pub as_number: i64,
    /// <p>The name of the country where the internet event is located.</p>
    pub country: ::std::string::String,
    /// <p>The subdivision location where the health event is located. The subdivision usually maps to states in most countries (including the United States). For United Kingdom, it maps to a country (England, Scotland, Wales) or province (Northern Ireland).</p>
    pub subdivision: ::std::option::Option<::std::string::String>,
    /// <p>The metro area where the health event is located.</p>
    /// <p>Metro indicates a metropolitan region in the United States, such as the region around New York City. In non-US countries, this is a second-level subdivision. For example, in the United Kingdom, it could be a county, a London borough, a unitary authority, council area, and so on.</p>
    pub metro: ::std::option::Option<::std::string::String>,
    /// <p>The name of the city where the internet event is located.</p>
    pub city: ::std::string::String,
    /// <p>The latitude where the internet event is located.</p>
    pub latitude: f64,
    /// <p>The longitude where the internet event is located.</p>
    pub longitude: f64,
}
impl ClientLocation {
    /// <p>The name of the internet service provider (ISP) or network (ASN).</p>
    pub fn as_name(&self) -> &str {
        use std::ops::Deref;
        self.as_name.deref()
    }
    /// <p>The Autonomous System Number (ASN) of the network at an impacted location.</p>
    pub fn as_number(&self) -> i64 {
        self.as_number
    }
    /// <p>The name of the country where the internet event is located.</p>
    pub fn country(&self) -> &str {
        use std::ops::Deref;
        self.country.deref()
    }
    /// <p>The subdivision location where the health event is located. The subdivision usually maps to states in most countries (including the United States). For United Kingdom, it maps to a country (England, Scotland, Wales) or province (Northern Ireland).</p>
    pub fn subdivision(&self) -> ::std::option::Option<&str> {
        self.subdivision.as_deref()
    }
    /// <p>The metro area where the health event is located.</p>
    /// <p>Metro indicates a metropolitan region in the United States, such as the region around New York City. In non-US countries, this is a second-level subdivision. For example, in the United Kingdom, it could be a county, a London borough, a unitary authority, council area, and so on.</p>
    pub fn metro(&self) -> ::std::option::Option<&str> {
        self.metro.as_deref()
    }
    /// <p>The name of the city where the internet event is located.</p>
    pub fn city(&self) -> &str {
        use std::ops::Deref;
        self.city.deref()
    }
    /// <p>The latitude where the internet event is located.</p>
    pub fn latitude(&self) -> f64 {
        self.latitude
    }
    /// <p>The longitude where the internet event is located.</p>
    pub fn longitude(&self) -> f64 {
        self.longitude
    }
}
impl ClientLocation {
    /// Creates a new builder-style object to manufacture [`ClientLocation`](crate::types::ClientLocation).
    pub fn builder() -> crate::types::builders::ClientLocationBuilder {
        crate::types::builders::ClientLocationBuilder::default()
    }
}

/// A builder for [`ClientLocation`](crate::types::ClientLocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClientLocationBuilder {
    pub(crate) as_name: ::std::option::Option<::std::string::String>,
    pub(crate) as_number: ::std::option::Option<i64>,
    pub(crate) country: ::std::option::Option<::std::string::String>,
    pub(crate) subdivision: ::std::option::Option<::std::string::String>,
    pub(crate) metro: ::std::option::Option<::std::string::String>,
    pub(crate) city: ::std::option::Option<::std::string::String>,
    pub(crate) latitude: ::std::option::Option<f64>,
    pub(crate) longitude: ::std::option::Option<f64>,
}
impl ClientLocationBuilder {
    /// <p>The name of the internet service provider (ISP) or network (ASN).</p>
    /// This field is required.
    pub fn as_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.as_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the internet service provider (ISP) or network (ASN).</p>
    pub fn set_as_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.as_name = input;
        self
    }
    /// <p>The name of the internet service provider (ISP) or network (ASN).</p>
    pub fn get_as_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.as_name
    }
    /// <p>The Autonomous System Number (ASN) of the network at an impacted location.</p>
    /// This field is required.
    pub fn as_number(mut self, input: i64) -> Self {
        self.as_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Autonomous System Number (ASN) of the network at an impacted location.</p>
    pub fn set_as_number(mut self, input: ::std::option::Option<i64>) -> Self {
        self.as_number = input;
        self
    }
    /// <p>The Autonomous System Number (ASN) of the network at an impacted location.</p>
    pub fn get_as_number(&self) -> &::std::option::Option<i64> {
        &self.as_number
    }
    /// <p>The name of the country where the internet event is located.</p>
    /// This field is required.
    pub fn country(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.country = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the country where the internet event is located.</p>
    pub fn set_country(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.country = input;
        self
    }
    /// <p>The name of the country where the internet event is located.</p>
    pub fn get_country(&self) -> &::std::option::Option<::std::string::String> {
        &self.country
    }
    /// <p>The subdivision location where the health event is located. The subdivision usually maps to states in most countries (including the United States). For United Kingdom, it maps to a country (England, Scotland, Wales) or province (Northern Ireland).</p>
    pub fn subdivision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subdivision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subdivision location where the health event is located. The subdivision usually maps to states in most countries (including the United States). For United Kingdom, it maps to a country (England, Scotland, Wales) or province (Northern Ireland).</p>
    pub fn set_subdivision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subdivision = input;
        self
    }
    /// <p>The subdivision location where the health event is located. The subdivision usually maps to states in most countries (including the United States). For United Kingdom, it maps to a country (England, Scotland, Wales) or province (Northern Ireland).</p>
    pub fn get_subdivision(&self) -> &::std::option::Option<::std::string::String> {
        &self.subdivision
    }
    /// <p>The metro area where the health event is located.</p>
    /// <p>Metro indicates a metropolitan region in the United States, such as the region around New York City. In non-US countries, this is a second-level subdivision. For example, in the United Kingdom, it could be a county, a London borough, a unitary authority, council area, and so on.</p>
    pub fn metro(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metro = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metro area where the health event is located.</p>
    /// <p>Metro indicates a metropolitan region in the United States, such as the region around New York City. In non-US countries, this is a second-level subdivision. For example, in the United Kingdom, it could be a county, a London borough, a unitary authority, council area, and so on.</p>
    pub fn set_metro(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metro = input;
        self
    }
    /// <p>The metro area where the health event is located.</p>
    /// <p>Metro indicates a metropolitan region in the United States, such as the region around New York City. In non-US countries, this is a second-level subdivision. For example, in the United Kingdom, it could be a county, a London borough, a unitary authority, council area, and so on.</p>
    pub fn get_metro(&self) -> &::std::option::Option<::std::string::String> {
        &self.metro
    }
    /// <p>The name of the city where the internet event is located.</p>
    /// This field is required.
    pub fn city(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.city = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the city where the internet event is located.</p>
    pub fn set_city(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.city = input;
        self
    }
    /// <p>The name of the city where the internet event is located.</p>
    pub fn get_city(&self) -> &::std::option::Option<::std::string::String> {
        &self.city
    }
    /// <p>The latitude where the internet event is located.</p>
    /// This field is required.
    pub fn latitude(mut self, input: f64) -> Self {
        self.latitude = ::std::option::Option::Some(input);
        self
    }
    /// <p>The latitude where the internet event is located.</p>
    pub fn set_latitude(mut self, input: ::std::option::Option<f64>) -> Self {
        self.latitude = input;
        self
    }
    /// <p>The latitude where the internet event is located.</p>
    pub fn get_latitude(&self) -> &::std::option::Option<f64> {
        &self.latitude
    }
    /// <p>The longitude where the internet event is located.</p>
    /// This field is required.
    pub fn longitude(mut self, input: f64) -> Self {
        self.longitude = ::std::option::Option::Some(input);
        self
    }
    /// <p>The longitude where the internet event is located.</p>
    pub fn set_longitude(mut self, input: ::std::option::Option<f64>) -> Self {
        self.longitude = input;
        self
    }
    /// <p>The longitude where the internet event is located.</p>
    pub fn get_longitude(&self) -> &::std::option::Option<f64> {
        &self.longitude
    }
    /// Consumes the builder and constructs a [`ClientLocation`](crate::types::ClientLocation).
    /// This method will fail if any of the following fields are not set:
    /// - [`as_name`](crate::types::builders::ClientLocationBuilder::as_name)
    /// - [`as_number`](crate::types::builders::ClientLocationBuilder::as_number)
    /// - [`country`](crate::types::builders::ClientLocationBuilder::country)
    /// - [`city`](crate::types::builders::ClientLocationBuilder::city)
    /// - [`latitude`](crate::types::builders::ClientLocationBuilder::latitude)
    /// - [`longitude`](crate::types::builders::ClientLocationBuilder::longitude)
    pub fn build(self) -> ::std::result::Result<crate::types::ClientLocation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ClientLocation {
            as_name: self.as_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "as_name",
                    "as_name was not specified but it is required when building ClientLocation",
                )
            })?,
            as_number: self.as_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "as_number",
                    "as_number was not specified but it is required when building ClientLocation",
                )
            })?,
            country: self.country.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "country",
                    "country was not specified but it is required when building ClientLocation",
                )
            })?,
            subdivision: self.subdivision,
            metro: self.metro,
            city: self.city.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "city",
                    "city was not specified but it is required when building ClientLocation",
                )
            })?,
            latitude: self.latitude.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "latitude",
                    "latitude was not specified but it is required when building ClientLocation",
                )
            })?,
            longitude: self.longitude.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "longitude",
                    "longitude was not specified but it is required when building ClientLocation",
                )
            })?,
        })
    }
}
