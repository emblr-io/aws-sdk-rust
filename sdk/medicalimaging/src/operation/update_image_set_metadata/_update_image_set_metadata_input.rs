// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateImageSetMetadataInput {
    /// <p>The data store identifier.</p>
    pub datastore_id: ::std::option::Option<::std::string::String>,
    /// <p>The image set identifier.</p>
    pub image_set_id: ::std::option::Option<::std::string::String>,
    /// <p>The latest image set version identifier.</p>
    pub latest_version_id: ::std::option::Option<::std::string::String>,
    /// <p>Setting this flag will force the <code>UpdateImageSetMetadata</code> operation for the following attributes:</p>
    /// <ul>
    /// <li>
    /// <p><code>Tag.StudyInstanceUID</code>, <code>Tag.SeriesInstanceUID</code>, <code>Tag.SOPInstanceUID</code>, and <code>Tag.StudyID</code></p></li>
    /// <li>
    /// <p>Adding, removing, or updating private tags for an individual SOP Instance</p></li>
    /// </ul>
    pub force: ::std::option::Option<bool>,
    /// <p>Update image set metadata updates.</p>
    pub update_image_set_metadata_updates: ::std::option::Option<crate::types::MetadataUpdates>,
}
impl UpdateImageSetMetadataInput {
    /// <p>The data store identifier.</p>
    pub fn datastore_id(&self) -> ::std::option::Option<&str> {
        self.datastore_id.as_deref()
    }
    /// <p>The image set identifier.</p>
    pub fn image_set_id(&self) -> ::std::option::Option<&str> {
        self.image_set_id.as_deref()
    }
    /// <p>The latest image set version identifier.</p>
    pub fn latest_version_id(&self) -> ::std::option::Option<&str> {
        self.latest_version_id.as_deref()
    }
    /// <p>Setting this flag will force the <code>UpdateImageSetMetadata</code> operation for the following attributes:</p>
    /// <ul>
    /// <li>
    /// <p><code>Tag.StudyInstanceUID</code>, <code>Tag.SeriesInstanceUID</code>, <code>Tag.SOPInstanceUID</code>, and <code>Tag.StudyID</code></p></li>
    /// <li>
    /// <p>Adding, removing, or updating private tags for an individual SOP Instance</p></li>
    /// </ul>
    pub fn force(&self) -> ::std::option::Option<bool> {
        self.force
    }
    /// <p>Update image set metadata updates.</p>
    pub fn update_image_set_metadata_updates(&self) -> ::std::option::Option<&crate::types::MetadataUpdates> {
        self.update_image_set_metadata_updates.as_ref()
    }
}
impl UpdateImageSetMetadataInput {
    /// Creates a new builder-style object to manufacture [`UpdateImageSetMetadataInput`](crate::operation::update_image_set_metadata::UpdateImageSetMetadataInput).
    pub fn builder() -> crate::operation::update_image_set_metadata::builders::UpdateImageSetMetadataInputBuilder {
        crate::operation::update_image_set_metadata::builders::UpdateImageSetMetadataInputBuilder::default()
    }
}

/// A builder for [`UpdateImageSetMetadataInput`](crate::operation::update_image_set_metadata::UpdateImageSetMetadataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateImageSetMetadataInputBuilder {
    pub(crate) datastore_id: ::std::option::Option<::std::string::String>,
    pub(crate) image_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) latest_version_id: ::std::option::Option<::std::string::String>,
    pub(crate) force: ::std::option::Option<bool>,
    pub(crate) update_image_set_metadata_updates: ::std::option::Option<crate::types::MetadataUpdates>,
}
impl UpdateImageSetMetadataInputBuilder {
    /// <p>The data store identifier.</p>
    /// This field is required.
    pub fn datastore_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.datastore_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The data store identifier.</p>
    pub fn set_datastore_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.datastore_id = input;
        self
    }
    /// <p>The data store identifier.</p>
    pub fn get_datastore_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.datastore_id
    }
    /// <p>The image set identifier.</p>
    /// This field is required.
    pub fn image_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The image set identifier.</p>
    pub fn set_image_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_set_id = input;
        self
    }
    /// <p>The image set identifier.</p>
    pub fn get_image_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_set_id
    }
    /// <p>The latest image set version identifier.</p>
    /// This field is required.
    pub fn latest_version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.latest_version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The latest image set version identifier.</p>
    pub fn set_latest_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.latest_version_id = input;
        self
    }
    /// <p>The latest image set version identifier.</p>
    pub fn get_latest_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.latest_version_id
    }
    /// <p>Setting this flag will force the <code>UpdateImageSetMetadata</code> operation for the following attributes:</p>
    /// <ul>
    /// <li>
    /// <p><code>Tag.StudyInstanceUID</code>, <code>Tag.SeriesInstanceUID</code>, <code>Tag.SOPInstanceUID</code>, and <code>Tag.StudyID</code></p></li>
    /// <li>
    /// <p>Adding, removing, or updating private tags for an individual SOP Instance</p></li>
    /// </ul>
    pub fn force(mut self, input: bool) -> Self {
        self.force = ::std::option::Option::Some(input);
        self
    }
    /// <p>Setting this flag will force the <code>UpdateImageSetMetadata</code> operation for the following attributes:</p>
    /// <ul>
    /// <li>
    /// <p><code>Tag.StudyInstanceUID</code>, <code>Tag.SeriesInstanceUID</code>, <code>Tag.SOPInstanceUID</code>, and <code>Tag.StudyID</code></p></li>
    /// <li>
    /// <p>Adding, removing, or updating private tags for an individual SOP Instance</p></li>
    /// </ul>
    pub fn set_force(mut self, input: ::std::option::Option<bool>) -> Self {
        self.force = input;
        self
    }
    /// <p>Setting this flag will force the <code>UpdateImageSetMetadata</code> operation for the following attributes:</p>
    /// <ul>
    /// <li>
    /// <p><code>Tag.StudyInstanceUID</code>, <code>Tag.SeriesInstanceUID</code>, <code>Tag.SOPInstanceUID</code>, and <code>Tag.StudyID</code></p></li>
    /// <li>
    /// <p>Adding, removing, or updating private tags for an individual SOP Instance</p></li>
    /// </ul>
    pub fn get_force(&self) -> &::std::option::Option<bool> {
        &self.force
    }
    /// <p>Update image set metadata updates.</p>
    /// This field is required.
    pub fn update_image_set_metadata_updates(mut self, input: crate::types::MetadataUpdates) -> Self {
        self.update_image_set_metadata_updates = ::std::option::Option::Some(input);
        self
    }
    /// <p>Update image set metadata updates.</p>
    pub fn set_update_image_set_metadata_updates(mut self, input: ::std::option::Option<crate::types::MetadataUpdates>) -> Self {
        self.update_image_set_metadata_updates = input;
        self
    }
    /// <p>Update image set metadata updates.</p>
    pub fn get_update_image_set_metadata_updates(&self) -> &::std::option::Option<crate::types::MetadataUpdates> {
        &self.update_image_set_metadata_updates
    }
    /// Consumes the builder and constructs a [`UpdateImageSetMetadataInput`](crate::operation::update_image_set_metadata::UpdateImageSetMetadataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_image_set_metadata::UpdateImageSetMetadataInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_image_set_metadata::UpdateImageSetMetadataInput {
            datastore_id: self.datastore_id,
            image_set_id: self.image_set_id,
            latest_version_id: self.latest_version_id,
            force: self.force,
            update_image_set_metadata_updates: self.update_image_set_metadata_updates,
        })
    }
}
