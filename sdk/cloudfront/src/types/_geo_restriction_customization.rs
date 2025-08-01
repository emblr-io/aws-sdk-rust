// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The customizations that you specified for the distribution tenant for geographic restrictions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GeoRestrictionCustomization {
    /// <p>The method that you want to use to restrict distribution of your content by country:</p>
    /// <ul>
    /// <li>
    /// <p><code>none</code>: No geographic restriction is enabled, meaning access to content is not restricted by client geo location.</p></li>
    /// <li>
    /// <p><code>blacklist</code>: The <code>Location</code> elements specify the countries in which you don't want CloudFront to distribute your content.</p></li>
    /// <li>
    /// <p><code>whitelist</code>: The <code>Location</code> elements specify the countries in which you want CloudFront to distribute your content.</p></li>
    /// </ul>
    pub restriction_type: crate::types::GeoRestrictionType,
    /// <p>The locations for geographic restrictions.</p>
    pub locations: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GeoRestrictionCustomization {
    /// <p>The method that you want to use to restrict distribution of your content by country:</p>
    /// <ul>
    /// <li>
    /// <p><code>none</code>: No geographic restriction is enabled, meaning access to content is not restricted by client geo location.</p></li>
    /// <li>
    /// <p><code>blacklist</code>: The <code>Location</code> elements specify the countries in which you don't want CloudFront to distribute your content.</p></li>
    /// <li>
    /// <p><code>whitelist</code>: The <code>Location</code> elements specify the countries in which you want CloudFront to distribute your content.</p></li>
    /// </ul>
    pub fn restriction_type(&self) -> &crate::types::GeoRestrictionType {
        &self.restriction_type
    }
    /// <p>The locations for geographic restrictions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.locations.is_none()`.
    pub fn locations(&self) -> &[::std::string::String] {
        self.locations.as_deref().unwrap_or_default()
    }
}
impl GeoRestrictionCustomization {
    /// Creates a new builder-style object to manufacture [`GeoRestrictionCustomization`](crate::types::GeoRestrictionCustomization).
    pub fn builder() -> crate::types::builders::GeoRestrictionCustomizationBuilder {
        crate::types::builders::GeoRestrictionCustomizationBuilder::default()
    }
}

/// A builder for [`GeoRestrictionCustomization`](crate::types::GeoRestrictionCustomization).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GeoRestrictionCustomizationBuilder {
    pub(crate) restriction_type: ::std::option::Option<crate::types::GeoRestrictionType>,
    pub(crate) locations: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl GeoRestrictionCustomizationBuilder {
    /// <p>The method that you want to use to restrict distribution of your content by country:</p>
    /// <ul>
    /// <li>
    /// <p><code>none</code>: No geographic restriction is enabled, meaning access to content is not restricted by client geo location.</p></li>
    /// <li>
    /// <p><code>blacklist</code>: The <code>Location</code> elements specify the countries in which you don't want CloudFront to distribute your content.</p></li>
    /// <li>
    /// <p><code>whitelist</code>: The <code>Location</code> elements specify the countries in which you want CloudFront to distribute your content.</p></li>
    /// </ul>
    /// This field is required.
    pub fn restriction_type(mut self, input: crate::types::GeoRestrictionType) -> Self {
        self.restriction_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The method that you want to use to restrict distribution of your content by country:</p>
    /// <ul>
    /// <li>
    /// <p><code>none</code>: No geographic restriction is enabled, meaning access to content is not restricted by client geo location.</p></li>
    /// <li>
    /// <p><code>blacklist</code>: The <code>Location</code> elements specify the countries in which you don't want CloudFront to distribute your content.</p></li>
    /// <li>
    /// <p><code>whitelist</code>: The <code>Location</code> elements specify the countries in which you want CloudFront to distribute your content.</p></li>
    /// </ul>
    pub fn set_restriction_type(mut self, input: ::std::option::Option<crate::types::GeoRestrictionType>) -> Self {
        self.restriction_type = input;
        self
    }
    /// <p>The method that you want to use to restrict distribution of your content by country:</p>
    /// <ul>
    /// <li>
    /// <p><code>none</code>: No geographic restriction is enabled, meaning access to content is not restricted by client geo location.</p></li>
    /// <li>
    /// <p><code>blacklist</code>: The <code>Location</code> elements specify the countries in which you don't want CloudFront to distribute your content.</p></li>
    /// <li>
    /// <p><code>whitelist</code>: The <code>Location</code> elements specify the countries in which you want CloudFront to distribute your content.</p></li>
    /// </ul>
    pub fn get_restriction_type(&self) -> &::std::option::Option<crate::types::GeoRestrictionType> {
        &self.restriction_type
    }
    /// Appends an item to `locations`.
    ///
    /// To override the contents of this collection use [`set_locations`](Self::set_locations).
    ///
    /// <p>The locations for geographic restrictions.</p>
    pub fn locations(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.locations.unwrap_or_default();
        v.push(input.into());
        self.locations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The locations for geographic restrictions.</p>
    pub fn set_locations(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.locations = input;
        self
    }
    /// <p>The locations for geographic restrictions.</p>
    pub fn get_locations(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.locations
    }
    /// Consumes the builder and constructs a [`GeoRestrictionCustomization`](crate::types::GeoRestrictionCustomization).
    /// This method will fail if any of the following fields are not set:
    /// - [`restriction_type`](crate::types::builders::GeoRestrictionCustomizationBuilder::restriction_type)
    pub fn build(self) -> ::std::result::Result<crate::types::GeoRestrictionCustomization, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GeoRestrictionCustomization {
            restriction_type: self.restriction_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "restriction_type",
                    "restriction_type was not specified but it is required when building GeoRestrictionCustomization",
                )
            })?,
            locations: self.locations,
        })
    }
}
