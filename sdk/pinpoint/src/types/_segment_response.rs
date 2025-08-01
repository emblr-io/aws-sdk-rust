// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about the configuration, dimension, and other settings for a segment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SegmentResponse {
    /// <p>The unique identifier for the application that the segment is associated with.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the segment.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The date and time when the segment was created.</p>
    pub creation_date: ::std::option::Option<::std::string::String>,
    /// <p>The dimension settings for the segment.</p>
    pub dimensions: ::std::option::Option<crate::types::SegmentDimensions>,
    /// <p>The unique identifier for the segment.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The settings for the import job that's associated with the segment.</p>
    pub import_definition: ::std::option::Option<crate::types::SegmentImportResource>,
    /// <p>The date and time when the segment was last modified.</p>
    pub last_modified_date: ::std::option::Option<::std::string::String>,
    /// <p>The name of the segment.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A list of one or more segment groups that apply to the segment. Each segment group consists of zero or more base segments and the dimensions that are applied to those base segments.</p>
    pub segment_groups: ::std::option::Option<crate::types::SegmentGroupList>,
    /// <p>The segment type. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>DIMENSIONAL - A dynamic segment, which is a segment that uses selection criteria that you specify and is based on endpoint data that's reported by your app. Dynamic segments can change over time.</p></li>
    /// <li>
    /// <p>IMPORT - A static segment, which is a segment that uses selection criteria that you specify and is based on endpoint definitions that you import from a file. Imported segments are static; they don't change over time.</p></li>
    /// </ul>
    pub segment_type: ::std::option::Option<crate::types::SegmentType>,
    /// <p>A string-to-string map of key-value pairs that identifies the tags that are associated with the segment. Each tag consists of a required tag key and an associated tag value.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The version number of the segment.</p>
    pub version: ::std::option::Option<i32>,
}
impl SegmentResponse {
    /// <p>The unique identifier for the application that the segment is associated with.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the segment.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The date and time when the segment was created.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&str> {
        self.creation_date.as_deref()
    }
    /// <p>The dimension settings for the segment.</p>
    pub fn dimensions(&self) -> ::std::option::Option<&crate::types::SegmentDimensions> {
        self.dimensions.as_ref()
    }
    /// <p>The unique identifier for the segment.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The settings for the import job that's associated with the segment.</p>
    pub fn import_definition(&self) -> ::std::option::Option<&crate::types::SegmentImportResource> {
        self.import_definition.as_ref()
    }
    /// <p>The date and time when the segment was last modified.</p>
    pub fn last_modified_date(&self) -> ::std::option::Option<&str> {
        self.last_modified_date.as_deref()
    }
    /// <p>The name of the segment.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A list of one or more segment groups that apply to the segment. Each segment group consists of zero or more base segments and the dimensions that are applied to those base segments.</p>
    pub fn segment_groups(&self) -> ::std::option::Option<&crate::types::SegmentGroupList> {
        self.segment_groups.as_ref()
    }
    /// <p>The segment type. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>DIMENSIONAL - A dynamic segment, which is a segment that uses selection criteria that you specify and is based on endpoint data that's reported by your app. Dynamic segments can change over time.</p></li>
    /// <li>
    /// <p>IMPORT - A static segment, which is a segment that uses selection criteria that you specify and is based on endpoint definitions that you import from a file. Imported segments are static; they don't change over time.</p></li>
    /// </ul>
    pub fn segment_type(&self) -> ::std::option::Option<&crate::types::SegmentType> {
        self.segment_type.as_ref()
    }
    /// <p>A string-to-string map of key-value pairs that identifies the tags that are associated with the segment. Each tag consists of a required tag key and an associated tag value.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The version number of the segment.</p>
    pub fn version(&self) -> ::std::option::Option<i32> {
        self.version
    }
}
impl SegmentResponse {
    /// Creates a new builder-style object to manufacture [`SegmentResponse`](crate::types::SegmentResponse).
    pub fn builder() -> crate::types::builders::SegmentResponseBuilder {
        crate::types::builders::SegmentResponseBuilder::default()
    }
}

/// A builder for [`SegmentResponse`](crate::types::SegmentResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SegmentResponseBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::std::string::String>,
    pub(crate) dimensions: ::std::option::Option<crate::types::SegmentDimensions>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) import_definition: ::std::option::Option<crate::types::SegmentImportResource>,
    pub(crate) last_modified_date: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) segment_groups: ::std::option::Option<crate::types::SegmentGroupList>,
    pub(crate) segment_type: ::std::option::Option<crate::types::SegmentType>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) version: ::std::option::Option<i32>,
}
impl SegmentResponseBuilder {
    /// <p>The unique identifier for the application that the segment is associated with.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the application that the segment is associated with.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The unique identifier for the application that the segment is associated with.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The Amazon Resource Name (ARN) of the segment.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the segment.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the segment.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The date and time when the segment was created.</p>
    /// This field is required.
    pub fn creation_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creation_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time when the segment was created.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date and time when the segment was created.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.creation_date
    }
    /// <p>The dimension settings for the segment.</p>
    pub fn dimensions(mut self, input: crate::types::SegmentDimensions) -> Self {
        self.dimensions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The dimension settings for the segment.</p>
    pub fn set_dimensions(mut self, input: ::std::option::Option<crate::types::SegmentDimensions>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>The dimension settings for the segment.</p>
    pub fn get_dimensions(&self) -> &::std::option::Option<crate::types::SegmentDimensions> {
        &self.dimensions
    }
    /// <p>The unique identifier for the segment.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the segment.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the segment.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The settings for the import job that's associated with the segment.</p>
    pub fn import_definition(mut self, input: crate::types::SegmentImportResource) -> Self {
        self.import_definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The settings for the import job that's associated with the segment.</p>
    pub fn set_import_definition(mut self, input: ::std::option::Option<crate::types::SegmentImportResource>) -> Self {
        self.import_definition = input;
        self
    }
    /// <p>The settings for the import job that's associated with the segment.</p>
    pub fn get_import_definition(&self) -> &::std::option::Option<crate::types::SegmentImportResource> {
        &self.import_definition
    }
    /// <p>The date and time when the segment was last modified.</p>
    pub fn last_modified_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time when the segment was last modified.</p>
    pub fn set_last_modified_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_date = input;
        self
    }
    /// <p>The date and time when the segment was last modified.</p>
    pub fn get_last_modified_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_date
    }
    /// <p>The name of the segment.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the segment.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the segment.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A list of one or more segment groups that apply to the segment. Each segment group consists of zero or more base segments and the dimensions that are applied to those base segments.</p>
    pub fn segment_groups(mut self, input: crate::types::SegmentGroupList) -> Self {
        self.segment_groups = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of one or more segment groups that apply to the segment. Each segment group consists of zero or more base segments and the dimensions that are applied to those base segments.</p>
    pub fn set_segment_groups(mut self, input: ::std::option::Option<crate::types::SegmentGroupList>) -> Self {
        self.segment_groups = input;
        self
    }
    /// <p>A list of one or more segment groups that apply to the segment. Each segment group consists of zero or more base segments and the dimensions that are applied to those base segments.</p>
    pub fn get_segment_groups(&self) -> &::std::option::Option<crate::types::SegmentGroupList> {
        &self.segment_groups
    }
    /// <p>The segment type. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>DIMENSIONAL - A dynamic segment, which is a segment that uses selection criteria that you specify and is based on endpoint data that's reported by your app. Dynamic segments can change over time.</p></li>
    /// <li>
    /// <p>IMPORT - A static segment, which is a segment that uses selection criteria that you specify and is based on endpoint definitions that you import from a file. Imported segments are static; they don't change over time.</p></li>
    /// </ul>
    /// This field is required.
    pub fn segment_type(mut self, input: crate::types::SegmentType) -> Self {
        self.segment_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The segment type. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>DIMENSIONAL - A dynamic segment, which is a segment that uses selection criteria that you specify and is based on endpoint data that's reported by your app. Dynamic segments can change over time.</p></li>
    /// <li>
    /// <p>IMPORT - A static segment, which is a segment that uses selection criteria that you specify and is based on endpoint definitions that you import from a file. Imported segments are static; they don't change over time.</p></li>
    /// </ul>
    pub fn set_segment_type(mut self, input: ::std::option::Option<crate::types::SegmentType>) -> Self {
        self.segment_type = input;
        self
    }
    /// <p>The segment type. Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p>DIMENSIONAL - A dynamic segment, which is a segment that uses selection criteria that you specify and is based on endpoint data that's reported by your app. Dynamic segments can change over time.</p></li>
    /// <li>
    /// <p>IMPORT - A static segment, which is a segment that uses selection criteria that you specify and is based on endpoint definitions that you import from a file. Imported segments are static; they don't change over time.</p></li>
    /// </ul>
    pub fn get_segment_type(&self) -> &::std::option::Option<crate::types::SegmentType> {
        &self.segment_type
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A string-to-string map of key-value pairs that identifies the tags that are associated with the segment. Each tag consists of a required tag key and an associated tag value.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A string-to-string map of key-value pairs that identifies the tags that are associated with the segment. Each tag consists of a required tag key and an associated tag value.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A string-to-string map of key-value pairs that identifies the tags that are associated with the segment. Each tag consists of a required tag key and an associated tag value.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The version number of the segment.</p>
    pub fn version(mut self, input: i32) -> Self {
        self.version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version number of the segment.</p>
    pub fn set_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version number of the segment.</p>
    pub fn get_version(&self) -> &::std::option::Option<i32> {
        &self.version
    }
    /// Consumes the builder and constructs a [`SegmentResponse`](crate::types::SegmentResponse).
    pub fn build(self) -> crate::types::SegmentResponse {
        crate::types::SegmentResponse {
            application_id: self.application_id,
            arn: self.arn,
            creation_date: self.creation_date,
            dimensions: self.dimensions,
            id: self.id,
            import_definition: self.import_definition,
            last_modified_date: self.last_modified_date,
            name: self.name,
            segment_groups: self.segment_groups,
            segment_type: self.segment_type,
            tags: self.tags,
            version: self.version,
        }
    }
}
