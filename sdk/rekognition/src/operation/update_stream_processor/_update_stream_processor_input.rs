// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateStreamProcessorInput {
    /// <p>Name of the stream processor that you want to update.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The stream processor settings that you want to update. Label detection settings can be updated to detect different labels with a different minimum confidence.</p>
    pub settings_for_update: ::std::option::Option<crate::types::StreamProcessorSettingsForUpdate>,
    /// <p>Specifies locations in the frames where Amazon Rekognition checks for objects or people. This is an optional parameter for label detection stream processors.</p>
    pub regions_of_interest_for_update: ::std::option::Option<::std::vec::Vec<crate::types::RegionOfInterest>>,
    /// <p>Shows whether you are sharing data with Rekognition to improve model performance. You can choose this option at the account level or on a per-stream basis. Note that if you opt out at the account level this setting is ignored on individual streams.</p>
    pub data_sharing_preference_for_update: ::std::option::Option<crate::types::StreamProcessorDataSharingPreference>,
    /// <p>A list of parameters you want to delete from the stream processor.</p>
    pub parameters_to_delete: ::std::option::Option<::std::vec::Vec<crate::types::StreamProcessorParameterToDelete>>,
}
impl UpdateStreamProcessorInput {
    /// <p>Name of the stream processor that you want to update.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The stream processor settings that you want to update. Label detection settings can be updated to detect different labels with a different minimum confidence.</p>
    pub fn settings_for_update(&self) -> ::std::option::Option<&crate::types::StreamProcessorSettingsForUpdate> {
        self.settings_for_update.as_ref()
    }
    /// <p>Specifies locations in the frames where Amazon Rekognition checks for objects or people. This is an optional parameter for label detection stream processors.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.regions_of_interest_for_update.is_none()`.
    pub fn regions_of_interest_for_update(&self) -> &[crate::types::RegionOfInterest] {
        self.regions_of_interest_for_update.as_deref().unwrap_or_default()
    }
    /// <p>Shows whether you are sharing data with Rekognition to improve model performance. You can choose this option at the account level or on a per-stream basis. Note that if you opt out at the account level this setting is ignored on individual streams.</p>
    pub fn data_sharing_preference_for_update(&self) -> ::std::option::Option<&crate::types::StreamProcessorDataSharingPreference> {
        self.data_sharing_preference_for_update.as_ref()
    }
    /// <p>A list of parameters you want to delete from the stream processor.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameters_to_delete.is_none()`.
    pub fn parameters_to_delete(&self) -> &[crate::types::StreamProcessorParameterToDelete] {
        self.parameters_to_delete.as_deref().unwrap_or_default()
    }
}
impl UpdateStreamProcessorInput {
    /// Creates a new builder-style object to manufacture [`UpdateStreamProcessorInput`](crate::operation::update_stream_processor::UpdateStreamProcessorInput).
    pub fn builder() -> crate::operation::update_stream_processor::builders::UpdateStreamProcessorInputBuilder {
        crate::operation::update_stream_processor::builders::UpdateStreamProcessorInputBuilder::default()
    }
}

/// A builder for [`UpdateStreamProcessorInput`](crate::operation::update_stream_processor::UpdateStreamProcessorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateStreamProcessorInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) settings_for_update: ::std::option::Option<crate::types::StreamProcessorSettingsForUpdate>,
    pub(crate) regions_of_interest_for_update: ::std::option::Option<::std::vec::Vec<crate::types::RegionOfInterest>>,
    pub(crate) data_sharing_preference_for_update: ::std::option::Option<crate::types::StreamProcessorDataSharingPreference>,
    pub(crate) parameters_to_delete: ::std::option::Option<::std::vec::Vec<crate::types::StreamProcessorParameterToDelete>>,
}
impl UpdateStreamProcessorInputBuilder {
    /// <p>Name of the stream processor that you want to update.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the stream processor that you want to update.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the stream processor that you want to update.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The stream processor settings that you want to update. Label detection settings can be updated to detect different labels with a different minimum confidence.</p>
    pub fn settings_for_update(mut self, input: crate::types::StreamProcessorSettingsForUpdate) -> Self {
        self.settings_for_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>The stream processor settings that you want to update. Label detection settings can be updated to detect different labels with a different minimum confidence.</p>
    pub fn set_settings_for_update(mut self, input: ::std::option::Option<crate::types::StreamProcessorSettingsForUpdate>) -> Self {
        self.settings_for_update = input;
        self
    }
    /// <p>The stream processor settings that you want to update. Label detection settings can be updated to detect different labels with a different minimum confidence.</p>
    pub fn get_settings_for_update(&self) -> &::std::option::Option<crate::types::StreamProcessorSettingsForUpdate> {
        &self.settings_for_update
    }
    /// Appends an item to `regions_of_interest_for_update`.
    ///
    /// To override the contents of this collection use [`set_regions_of_interest_for_update`](Self::set_regions_of_interest_for_update).
    ///
    /// <p>Specifies locations in the frames where Amazon Rekognition checks for objects or people. This is an optional parameter for label detection stream processors.</p>
    pub fn regions_of_interest_for_update(mut self, input: crate::types::RegionOfInterest) -> Self {
        let mut v = self.regions_of_interest_for_update.unwrap_or_default();
        v.push(input);
        self.regions_of_interest_for_update = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies locations in the frames where Amazon Rekognition checks for objects or people. This is an optional parameter for label detection stream processors.</p>
    pub fn set_regions_of_interest_for_update(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RegionOfInterest>>) -> Self {
        self.regions_of_interest_for_update = input;
        self
    }
    /// <p>Specifies locations in the frames where Amazon Rekognition checks for objects or people. This is an optional parameter for label detection stream processors.</p>
    pub fn get_regions_of_interest_for_update(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RegionOfInterest>> {
        &self.regions_of_interest_for_update
    }
    /// <p>Shows whether you are sharing data with Rekognition to improve model performance. You can choose this option at the account level or on a per-stream basis. Note that if you opt out at the account level this setting is ignored on individual streams.</p>
    pub fn data_sharing_preference_for_update(mut self, input: crate::types::StreamProcessorDataSharingPreference) -> Self {
        self.data_sharing_preference_for_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Shows whether you are sharing data with Rekognition to improve model performance. You can choose this option at the account level or on a per-stream basis. Note that if you opt out at the account level this setting is ignored on individual streams.</p>
    pub fn set_data_sharing_preference_for_update(
        mut self,
        input: ::std::option::Option<crate::types::StreamProcessorDataSharingPreference>,
    ) -> Self {
        self.data_sharing_preference_for_update = input;
        self
    }
    /// <p>Shows whether you are sharing data with Rekognition to improve model performance. You can choose this option at the account level or on a per-stream basis. Note that if you opt out at the account level this setting is ignored on individual streams.</p>
    pub fn get_data_sharing_preference_for_update(&self) -> &::std::option::Option<crate::types::StreamProcessorDataSharingPreference> {
        &self.data_sharing_preference_for_update
    }
    /// Appends an item to `parameters_to_delete`.
    ///
    /// To override the contents of this collection use [`set_parameters_to_delete`](Self::set_parameters_to_delete).
    ///
    /// <p>A list of parameters you want to delete from the stream processor.</p>
    pub fn parameters_to_delete(mut self, input: crate::types::StreamProcessorParameterToDelete) -> Self {
        let mut v = self.parameters_to_delete.unwrap_or_default();
        v.push(input);
        self.parameters_to_delete = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of parameters you want to delete from the stream processor.</p>
    pub fn set_parameters_to_delete(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StreamProcessorParameterToDelete>>) -> Self {
        self.parameters_to_delete = input;
        self
    }
    /// <p>A list of parameters you want to delete from the stream processor.</p>
    pub fn get_parameters_to_delete(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StreamProcessorParameterToDelete>> {
        &self.parameters_to_delete
    }
    /// Consumes the builder and constructs a [`UpdateStreamProcessorInput`](crate::operation::update_stream_processor::UpdateStreamProcessorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_stream_processor::UpdateStreamProcessorInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_stream_processor::UpdateStreamProcessorInput {
            name: self.name,
            settings_for_update: self.settings_for_update,
            regions_of_interest_for_update: self.regions_of_interest_for_update,
            data_sharing_preference_for_update: self.data_sharing_preference_for_update,
            parameters_to_delete: self.parameters_to_delete,
        })
    }
}
