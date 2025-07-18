// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The response object for the Amazon FSx for NetApp ONTAP volume being deleted in the <code>DeleteVolume</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteVolumeOntapResponse {
    /// <p>The ID of the source backup. Specifies the backup that you are copying.</p>
    pub final_backup_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    pub final_backup_tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl DeleteVolumeOntapResponse {
    /// <p>The ID of the source backup. Specifies the backup that you are copying.</p>
    pub fn final_backup_id(&self) -> ::std::option::Option<&str> {
        self.final_backup_id.as_deref()
    }
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.final_backup_tags.is_none()`.
    pub fn final_backup_tags(&self) -> &[crate::types::Tag] {
        self.final_backup_tags.as_deref().unwrap_or_default()
    }
}
impl DeleteVolumeOntapResponse {
    /// Creates a new builder-style object to manufacture [`DeleteVolumeOntapResponse`](crate::types::DeleteVolumeOntapResponse).
    pub fn builder() -> crate::types::builders::DeleteVolumeOntapResponseBuilder {
        crate::types::builders::DeleteVolumeOntapResponseBuilder::default()
    }
}

/// A builder for [`DeleteVolumeOntapResponse`](crate::types::DeleteVolumeOntapResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteVolumeOntapResponseBuilder {
    pub(crate) final_backup_id: ::std::option::Option<::std::string::String>,
    pub(crate) final_backup_tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl DeleteVolumeOntapResponseBuilder {
    /// <p>The ID of the source backup. Specifies the backup that you are copying.</p>
    pub fn final_backup_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.final_backup_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the source backup. Specifies the backup that you are copying.</p>
    pub fn set_final_backup_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.final_backup_id = input;
        self
    }
    /// <p>The ID of the source backup. Specifies the backup that you are copying.</p>
    pub fn get_final_backup_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.final_backup_id
    }
    /// Appends an item to `final_backup_tags`.
    ///
    /// To override the contents of this collection use [`set_final_backup_tags`](Self::set_final_backup_tags).
    ///
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    pub fn final_backup_tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.final_backup_tags.unwrap_or_default();
        v.push(input);
        self.final_backup_tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    pub fn set_final_backup_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.final_backup_tags = input;
        self
    }
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    pub fn get_final_backup_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.final_backup_tags
    }
    /// Consumes the builder and constructs a [`DeleteVolumeOntapResponse`](crate::types::DeleteVolumeOntapResponse).
    pub fn build(self) -> crate::types::DeleteVolumeOntapResponse {
        crate::types::DeleteVolumeOntapResponse {
            final_backup_id: self.final_backup_id,
            final_backup_tags: self.final_backup_tags,
        }
    }
}
