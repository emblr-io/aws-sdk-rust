// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <important>
/// <p>End of support notice: Beginning October 1, 2025, Amazon S3 will stop returning <code>DisplayName</code>. Update your applications to use canonical IDs (unique identifier for Amazon Web Services accounts), Amazon Web Services account ID (12 digit identifier) or IAM ARNs (full resource naming) as a direct replacement of <code>DisplayName</code>.</p>
/// <p>This change affects the following Amazon Web Services Regions: US East (N. Virginia) Region, US West (N. California) Region, US West (Oregon) Region, Asia Pacific (Singapore) Region, Asia Pacific (Sydney) Region, Asia Pacific (Tokyo) Region, Europe (Ireland) Region, and South America (São Paulo) Region.</p>
/// </important>
/// <p>Container for the owner's display name and ID.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Owner {
    /// <p>Container for the display name of the owner. This value is only supported in the following Amazon Web Services Regions:</p>
    /// <ul>
    /// <li>
    /// <p>US East (N. Virginia)</p></li>
    /// <li>
    /// <p>US West (N. California)</p></li>
    /// <li>
    /// <p>US West (Oregon)</p></li>
    /// <li>
    /// <p>Asia Pacific (Singapore)</p></li>
    /// <li>
    /// <p>Asia Pacific (Sydney)</p></li>
    /// <li>
    /// <p>Asia Pacific (Tokyo)</p></li>
    /// <li>
    /// <p>Europe (Ireland)</p></li>
    /// <li>
    /// <p>South America (São Paulo)</p></li>
    /// </ul><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>Container for the ID of the owner.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl Owner {
    /// <p>Container for the display name of the owner. This value is only supported in the following Amazon Web Services Regions:</p>
    /// <ul>
    /// <li>
    /// <p>US East (N. Virginia)</p></li>
    /// <li>
    /// <p>US West (N. California)</p></li>
    /// <li>
    /// <p>US West (Oregon)</p></li>
    /// <li>
    /// <p>Asia Pacific (Singapore)</p></li>
    /// <li>
    /// <p>Asia Pacific (Sydney)</p></li>
    /// <li>
    /// <p>Asia Pacific (Tokyo)</p></li>
    /// <li>
    /// <p>Europe (Ireland)</p></li>
    /// <li>
    /// <p>South America (São Paulo)</p></li>
    /// </ul><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>Container for the ID of the owner.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl Owner {
    /// Creates a new builder-style object to manufacture [`Owner`](crate::types::Owner).
    pub fn builder() -> crate::types::builders::OwnerBuilder {
        crate::types::builders::OwnerBuilder::default()
    }
}

/// A builder for [`Owner`](crate::types::Owner).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OwnerBuilder {
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl OwnerBuilder {
    /// <p>Container for the display name of the owner. This value is only supported in the following Amazon Web Services Regions:</p>
    /// <ul>
    /// <li>
    /// <p>US East (N. Virginia)</p></li>
    /// <li>
    /// <p>US West (N. California)</p></li>
    /// <li>
    /// <p>US West (Oregon)</p></li>
    /// <li>
    /// <p>Asia Pacific (Singapore)</p></li>
    /// <li>
    /// <p>Asia Pacific (Sydney)</p></li>
    /// <li>
    /// <p>Asia Pacific (Tokyo)</p></li>
    /// <li>
    /// <p>Europe (Ireland)</p></li>
    /// <li>
    /// <p>South America (São Paulo)</p></li>
    /// </ul><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Container for the display name of the owner. This value is only supported in the following Amazon Web Services Regions:</p>
    /// <ul>
    /// <li>
    /// <p>US East (N. Virginia)</p></li>
    /// <li>
    /// <p>US West (N. California)</p></li>
    /// <li>
    /// <p>US West (Oregon)</p></li>
    /// <li>
    /// <p>Asia Pacific (Singapore)</p></li>
    /// <li>
    /// <p>Asia Pacific (Sydney)</p></li>
    /// <li>
    /// <p>Asia Pacific (Tokyo)</p></li>
    /// <li>
    /// <p>Europe (Ireland)</p></li>
    /// <li>
    /// <p>South America (São Paulo)</p></li>
    /// </ul><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>Container for the display name of the owner. This value is only supported in the following Amazon Web Services Regions:</p>
    /// <ul>
    /// <li>
    /// <p>US East (N. Virginia)</p></li>
    /// <li>
    /// <p>US West (N. California)</p></li>
    /// <li>
    /// <p>US West (Oregon)</p></li>
    /// <li>
    /// <p>Asia Pacific (Singapore)</p></li>
    /// <li>
    /// <p>Asia Pacific (Sydney)</p></li>
    /// <li>
    /// <p>Asia Pacific (Tokyo)</p></li>
    /// <li>
    /// <p>Europe (Ireland)</p></li>
    /// <li>
    /// <p>South America (São Paulo)</p></li>
    /// </ul><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>Container for the ID of the owner.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Container for the ID of the owner.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>Container for the ID of the owner.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`Owner`](crate::types::Owner).
    pub fn build(self) -> crate::types::Owner {
        crate::types::Owner {
            display_name: self.display_name,
            id: self.id,
        }
    }
}
