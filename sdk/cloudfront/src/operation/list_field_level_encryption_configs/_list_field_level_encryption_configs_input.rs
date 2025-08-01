// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFieldLevelEncryptionConfigsInput {
    /// <p>Use this when paginating results to indicate where to begin in your list of configurations. The results include configurations in the list that occur after the marker. To get the next page of results, set the <code>Marker</code> to the value of the <code>NextMarker</code> from the current page's response (which is also the ID of the last configuration on that page).</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of field-level encryption configurations you want in the response body.</p>
    pub max_items: ::std::option::Option<i32>,
}
impl ListFieldLevelEncryptionConfigsInput {
    /// <p>Use this when paginating results to indicate where to begin in your list of configurations. The results include configurations in the list that occur after the marker. To get the next page of results, set the <code>Marker</code> to the value of the <code>NextMarker</code> from the current page's response (which is also the ID of the last configuration on that page).</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>The maximum number of field-level encryption configurations you want in the response body.</p>
    pub fn max_items(&self) -> ::std::option::Option<i32> {
        self.max_items
    }
}
impl ListFieldLevelEncryptionConfigsInput {
    /// Creates a new builder-style object to manufacture [`ListFieldLevelEncryptionConfigsInput`](crate::operation::list_field_level_encryption_configs::ListFieldLevelEncryptionConfigsInput).
    pub fn builder() -> crate::operation::list_field_level_encryption_configs::builders::ListFieldLevelEncryptionConfigsInputBuilder {
        crate::operation::list_field_level_encryption_configs::builders::ListFieldLevelEncryptionConfigsInputBuilder::default()
    }
}

/// A builder for [`ListFieldLevelEncryptionConfigsInput`](crate::operation::list_field_level_encryption_configs::ListFieldLevelEncryptionConfigsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFieldLevelEncryptionConfigsInputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
}
impl ListFieldLevelEncryptionConfigsInputBuilder {
    /// <p>Use this when paginating results to indicate where to begin in your list of configurations. The results include configurations in the list that occur after the marker. To get the next page of results, set the <code>Marker</code> to the value of the <code>NextMarker</code> from the current page's response (which is also the ID of the last configuration on that page).</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Use this when paginating results to indicate where to begin in your list of configurations. The results include configurations in the list that occur after the marker. To get the next page of results, set the <code>Marker</code> to the value of the <code>NextMarker</code> from the current page's response (which is also the ID of the last configuration on that page).</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>Use this when paginating results to indicate where to begin in your list of configurations. The results include configurations in the list that occur after the marker. To get the next page of results, set the <code>Marker</code> to the value of the <code>NextMarker</code> from the current page's response (which is also the ID of the last configuration on that page).</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>The maximum number of field-level encryption configurations you want in the response body.</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of field-level encryption configurations you want in the response body.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>The maximum number of field-level encryption configurations you want in the response body.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// Consumes the builder and constructs a [`ListFieldLevelEncryptionConfigsInput`](crate::operation::list_field_level_encryption_configs::ListFieldLevelEncryptionConfigsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_field_level_encryption_configs::ListFieldLevelEncryptionConfigsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_field_level_encryption_configs::ListFieldLevelEncryptionConfigsInput {
                marker: self.marker,
                max_items: self.max_items,
            },
        )
    }
}
