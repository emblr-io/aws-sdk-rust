// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the tag keys to deregister for the current Region. You can either specify individual tag keys or deregister all tag keys in the current Region. You must specify either <code>IncludeAllTagsOfInstance</code> or <code>InstanceTagKeys</code> in the request</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregisterInstanceTagAttributeRequest {
    /// <p>Indicates whether to deregister all tag keys in the current Region. Specify <code>false</code> to deregister all tag keys.</p>
    pub include_all_tags_of_instance: ::std::option::Option<bool>,
    /// <p>Information about the tag keys to deregister.</p>
    pub instance_tag_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeregisterInstanceTagAttributeRequest {
    /// <p>Indicates whether to deregister all tag keys in the current Region. Specify <code>false</code> to deregister all tag keys.</p>
    pub fn include_all_tags_of_instance(&self) -> ::std::option::Option<bool> {
        self.include_all_tags_of_instance
    }
    /// <p>Information about the tag keys to deregister.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.instance_tag_keys.is_none()`.
    pub fn instance_tag_keys(&self) -> &[::std::string::String] {
        self.instance_tag_keys.as_deref().unwrap_or_default()
    }
}
impl DeregisterInstanceTagAttributeRequest {
    /// Creates a new builder-style object to manufacture [`DeregisterInstanceTagAttributeRequest`](crate::types::DeregisterInstanceTagAttributeRequest).
    pub fn builder() -> crate::types::builders::DeregisterInstanceTagAttributeRequestBuilder {
        crate::types::builders::DeregisterInstanceTagAttributeRequestBuilder::default()
    }
}

/// A builder for [`DeregisterInstanceTagAttributeRequest`](crate::types::DeregisterInstanceTagAttributeRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregisterInstanceTagAttributeRequestBuilder {
    pub(crate) include_all_tags_of_instance: ::std::option::Option<bool>,
    pub(crate) instance_tag_keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DeregisterInstanceTagAttributeRequestBuilder {
    /// <p>Indicates whether to deregister all tag keys in the current Region. Specify <code>false</code> to deregister all tag keys.</p>
    pub fn include_all_tags_of_instance(mut self, input: bool) -> Self {
        self.include_all_tags_of_instance = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to deregister all tag keys in the current Region. Specify <code>false</code> to deregister all tag keys.</p>
    pub fn set_include_all_tags_of_instance(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_all_tags_of_instance = input;
        self
    }
    /// <p>Indicates whether to deregister all tag keys in the current Region. Specify <code>false</code> to deregister all tag keys.</p>
    pub fn get_include_all_tags_of_instance(&self) -> &::std::option::Option<bool> {
        &self.include_all_tags_of_instance
    }
    /// Appends an item to `instance_tag_keys`.
    ///
    /// To override the contents of this collection use [`set_instance_tag_keys`](Self::set_instance_tag_keys).
    ///
    /// <p>Information about the tag keys to deregister.</p>
    pub fn instance_tag_keys(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.instance_tag_keys.unwrap_or_default();
        v.push(input.into());
        self.instance_tag_keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the tag keys to deregister.</p>
    pub fn set_instance_tag_keys(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.instance_tag_keys = input;
        self
    }
    /// <p>Information about the tag keys to deregister.</p>
    pub fn get_instance_tag_keys(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.instance_tag_keys
    }
    /// Consumes the builder and constructs a [`DeregisterInstanceTagAttributeRequest`](crate::types::DeregisterInstanceTagAttributeRequest).
    pub fn build(self) -> crate::types::DeregisterInstanceTagAttributeRequest {
        crate::types::DeregisterInstanceTagAttributeRequest {
            include_all_tags_of_instance: self.include_all_tags_of_instance,
            instance_tag_keys: self.instance_tag_keys,
        }
    }
}
