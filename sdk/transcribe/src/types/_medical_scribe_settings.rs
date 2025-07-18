// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Makes it possible to control how your Medical Scribe job is processed using a <code>MedicalScribeSettings</code> object. Specify <code>ChannelIdentification</code> if <code>ChannelDefinitions</code> are set. Enabled <code>ShowSpeakerLabels</code> if <code>ChannelIdentification</code> and <code>ChannelDefinitions</code> are not set. One and only one of <code>ChannelIdentification</code> and <code>ShowSpeakerLabels</code> must be set. If <code>ShowSpeakerLabels</code> is set, <code>MaxSpeakerLabels</code> must also be set. Use <code>Settings</code> to specify a vocabulary or vocabulary filter or both using <code>VocabularyName</code>, <code>VocabularyFilterName</code>. <code>VocabularyFilterMethod</code> must be specified if <code>VocabularyFilterName</code> is set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MedicalScribeSettings {
    /// <p>Enables speaker partitioning (diarization) in your Medical Scribe output. Speaker partitioning labels the speech from individual speakers in your media file.</p>
    /// <p>If you enable <code>ShowSpeakerLabels</code> in your request, you must also include <code>MaxSpeakerLabels</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/diarization.html">Partitioning speakers (diarization)</a>.</p>
    pub show_speaker_labels: ::std::option::Option<bool>,
    /// <p>Specify the maximum number of speakers you want to partition in your media.</p>
    /// <p>Note that if your media contains more speakers than the specified number, multiple speakers are treated as a single speaker.</p>
    /// <p>If you specify the <code>MaxSpeakerLabels</code> field, you must set the <code>ShowSpeakerLabels</code> field to true.</p>
    pub max_speaker_labels: ::std::option::Option<i32>,
    /// <p>Enables channel identification in multi-channel audio.</p>
    /// <p>Channel identification transcribes the audio on each channel independently, then appends the output for each channel into one transcript.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/channel-id.html">Transcribing multi-channel audio</a>.</p>
    pub channel_identification: ::std::option::Option<bool>,
    /// <p>The name of the custom vocabulary you want to include in your Medical Scribe request. Custom vocabulary names are case sensitive.</p>
    pub vocabulary_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the custom vocabulary filter you want to include in your Medical Scribe request. Custom vocabulary filter names are case sensitive.</p>
    /// <p>Note that if you include <code>VocabularyFilterName</code> in your request, you must also include <code>VocabularyFilterMethod</code>.</p>
    pub vocabulary_filter_name: ::std::option::Option<::std::string::String>,
    /// <p>Specify how you want your custom vocabulary filter applied to your transcript.</p>
    /// <p>To replace words with <code>***</code>, choose <code>mask</code>.</p>
    /// <p>To delete words, choose <code>remove</code>.</p>
    /// <p>To flag words without changing them, choose <code>tag</code>.</p>
    pub vocabulary_filter_method: ::std::option::Option<crate::types::VocabularyFilterMethod>,
    /// <p>Specify settings for the clinical note generation.</p>
    pub clinical_note_generation_settings: ::std::option::Option<crate::types::ClinicalNoteGenerationSettings>,
}
impl MedicalScribeSettings {
    /// <p>Enables speaker partitioning (diarization) in your Medical Scribe output. Speaker partitioning labels the speech from individual speakers in your media file.</p>
    /// <p>If you enable <code>ShowSpeakerLabels</code> in your request, you must also include <code>MaxSpeakerLabels</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/diarization.html">Partitioning speakers (diarization)</a>.</p>
    pub fn show_speaker_labels(&self) -> ::std::option::Option<bool> {
        self.show_speaker_labels
    }
    /// <p>Specify the maximum number of speakers you want to partition in your media.</p>
    /// <p>Note that if your media contains more speakers than the specified number, multiple speakers are treated as a single speaker.</p>
    /// <p>If you specify the <code>MaxSpeakerLabels</code> field, you must set the <code>ShowSpeakerLabels</code> field to true.</p>
    pub fn max_speaker_labels(&self) -> ::std::option::Option<i32> {
        self.max_speaker_labels
    }
    /// <p>Enables channel identification in multi-channel audio.</p>
    /// <p>Channel identification transcribes the audio on each channel independently, then appends the output for each channel into one transcript.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/channel-id.html">Transcribing multi-channel audio</a>.</p>
    pub fn channel_identification(&self) -> ::std::option::Option<bool> {
        self.channel_identification
    }
    /// <p>The name of the custom vocabulary you want to include in your Medical Scribe request. Custom vocabulary names are case sensitive.</p>
    pub fn vocabulary_name(&self) -> ::std::option::Option<&str> {
        self.vocabulary_name.as_deref()
    }
    /// <p>The name of the custom vocabulary filter you want to include in your Medical Scribe request. Custom vocabulary filter names are case sensitive.</p>
    /// <p>Note that if you include <code>VocabularyFilterName</code> in your request, you must also include <code>VocabularyFilterMethod</code>.</p>
    pub fn vocabulary_filter_name(&self) -> ::std::option::Option<&str> {
        self.vocabulary_filter_name.as_deref()
    }
    /// <p>Specify how you want your custom vocabulary filter applied to your transcript.</p>
    /// <p>To replace words with <code>***</code>, choose <code>mask</code>.</p>
    /// <p>To delete words, choose <code>remove</code>.</p>
    /// <p>To flag words without changing them, choose <code>tag</code>.</p>
    pub fn vocabulary_filter_method(&self) -> ::std::option::Option<&crate::types::VocabularyFilterMethod> {
        self.vocabulary_filter_method.as_ref()
    }
    /// <p>Specify settings for the clinical note generation.</p>
    pub fn clinical_note_generation_settings(&self) -> ::std::option::Option<&crate::types::ClinicalNoteGenerationSettings> {
        self.clinical_note_generation_settings.as_ref()
    }
}
impl MedicalScribeSettings {
    /// Creates a new builder-style object to manufacture [`MedicalScribeSettings`](crate::types::MedicalScribeSettings).
    pub fn builder() -> crate::types::builders::MedicalScribeSettingsBuilder {
        crate::types::builders::MedicalScribeSettingsBuilder::default()
    }
}

/// A builder for [`MedicalScribeSettings`](crate::types::MedicalScribeSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MedicalScribeSettingsBuilder {
    pub(crate) show_speaker_labels: ::std::option::Option<bool>,
    pub(crate) max_speaker_labels: ::std::option::Option<i32>,
    pub(crate) channel_identification: ::std::option::Option<bool>,
    pub(crate) vocabulary_name: ::std::option::Option<::std::string::String>,
    pub(crate) vocabulary_filter_name: ::std::option::Option<::std::string::String>,
    pub(crate) vocabulary_filter_method: ::std::option::Option<crate::types::VocabularyFilterMethod>,
    pub(crate) clinical_note_generation_settings: ::std::option::Option<crate::types::ClinicalNoteGenerationSettings>,
}
impl MedicalScribeSettingsBuilder {
    /// <p>Enables speaker partitioning (diarization) in your Medical Scribe output. Speaker partitioning labels the speech from individual speakers in your media file.</p>
    /// <p>If you enable <code>ShowSpeakerLabels</code> in your request, you must also include <code>MaxSpeakerLabels</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/diarization.html">Partitioning speakers (diarization)</a>.</p>
    pub fn show_speaker_labels(mut self, input: bool) -> Self {
        self.show_speaker_labels = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables speaker partitioning (diarization) in your Medical Scribe output. Speaker partitioning labels the speech from individual speakers in your media file.</p>
    /// <p>If you enable <code>ShowSpeakerLabels</code> in your request, you must also include <code>MaxSpeakerLabels</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/diarization.html">Partitioning speakers (diarization)</a>.</p>
    pub fn set_show_speaker_labels(mut self, input: ::std::option::Option<bool>) -> Self {
        self.show_speaker_labels = input;
        self
    }
    /// <p>Enables speaker partitioning (diarization) in your Medical Scribe output. Speaker partitioning labels the speech from individual speakers in your media file.</p>
    /// <p>If you enable <code>ShowSpeakerLabels</code> in your request, you must also include <code>MaxSpeakerLabels</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/diarization.html">Partitioning speakers (diarization)</a>.</p>
    pub fn get_show_speaker_labels(&self) -> &::std::option::Option<bool> {
        &self.show_speaker_labels
    }
    /// <p>Specify the maximum number of speakers you want to partition in your media.</p>
    /// <p>Note that if your media contains more speakers than the specified number, multiple speakers are treated as a single speaker.</p>
    /// <p>If you specify the <code>MaxSpeakerLabels</code> field, you must set the <code>ShowSpeakerLabels</code> field to true.</p>
    pub fn max_speaker_labels(mut self, input: i32) -> Self {
        self.max_speaker_labels = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify the maximum number of speakers you want to partition in your media.</p>
    /// <p>Note that if your media contains more speakers than the specified number, multiple speakers are treated as a single speaker.</p>
    /// <p>If you specify the <code>MaxSpeakerLabels</code> field, you must set the <code>ShowSpeakerLabels</code> field to true.</p>
    pub fn set_max_speaker_labels(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_speaker_labels = input;
        self
    }
    /// <p>Specify the maximum number of speakers you want to partition in your media.</p>
    /// <p>Note that if your media contains more speakers than the specified number, multiple speakers are treated as a single speaker.</p>
    /// <p>If you specify the <code>MaxSpeakerLabels</code> field, you must set the <code>ShowSpeakerLabels</code> field to true.</p>
    pub fn get_max_speaker_labels(&self) -> &::std::option::Option<i32> {
        &self.max_speaker_labels
    }
    /// <p>Enables channel identification in multi-channel audio.</p>
    /// <p>Channel identification transcribes the audio on each channel independently, then appends the output for each channel into one transcript.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/channel-id.html">Transcribing multi-channel audio</a>.</p>
    pub fn channel_identification(mut self, input: bool) -> Self {
        self.channel_identification = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables channel identification in multi-channel audio.</p>
    /// <p>Channel identification transcribes the audio on each channel independently, then appends the output for each channel into one transcript.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/channel-id.html">Transcribing multi-channel audio</a>.</p>
    pub fn set_channel_identification(mut self, input: ::std::option::Option<bool>) -> Self {
        self.channel_identification = input;
        self
    }
    /// <p>Enables channel identification in multi-channel audio.</p>
    /// <p>Channel identification transcribes the audio on each channel independently, then appends the output for each channel into one transcript.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/channel-id.html">Transcribing multi-channel audio</a>.</p>
    pub fn get_channel_identification(&self) -> &::std::option::Option<bool> {
        &self.channel_identification
    }
    /// <p>The name of the custom vocabulary you want to include in your Medical Scribe request. Custom vocabulary names are case sensitive.</p>
    pub fn vocabulary_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vocabulary_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom vocabulary you want to include in your Medical Scribe request. Custom vocabulary names are case sensitive.</p>
    pub fn set_vocabulary_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vocabulary_name = input;
        self
    }
    /// <p>The name of the custom vocabulary you want to include in your Medical Scribe request. Custom vocabulary names are case sensitive.</p>
    pub fn get_vocabulary_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.vocabulary_name
    }
    /// <p>The name of the custom vocabulary filter you want to include in your Medical Scribe request. Custom vocabulary filter names are case sensitive.</p>
    /// <p>Note that if you include <code>VocabularyFilterName</code> in your request, you must also include <code>VocabularyFilterMethod</code>.</p>
    pub fn vocabulary_filter_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vocabulary_filter_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom vocabulary filter you want to include in your Medical Scribe request. Custom vocabulary filter names are case sensitive.</p>
    /// <p>Note that if you include <code>VocabularyFilterName</code> in your request, you must also include <code>VocabularyFilterMethod</code>.</p>
    pub fn set_vocabulary_filter_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vocabulary_filter_name = input;
        self
    }
    /// <p>The name of the custom vocabulary filter you want to include in your Medical Scribe request. Custom vocabulary filter names are case sensitive.</p>
    /// <p>Note that if you include <code>VocabularyFilterName</code> in your request, you must also include <code>VocabularyFilterMethod</code>.</p>
    pub fn get_vocabulary_filter_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.vocabulary_filter_name
    }
    /// <p>Specify how you want your custom vocabulary filter applied to your transcript.</p>
    /// <p>To replace words with <code>***</code>, choose <code>mask</code>.</p>
    /// <p>To delete words, choose <code>remove</code>.</p>
    /// <p>To flag words without changing them, choose <code>tag</code>.</p>
    pub fn vocabulary_filter_method(mut self, input: crate::types::VocabularyFilterMethod) -> Self {
        self.vocabulary_filter_method = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify how you want your custom vocabulary filter applied to your transcript.</p>
    /// <p>To replace words with <code>***</code>, choose <code>mask</code>.</p>
    /// <p>To delete words, choose <code>remove</code>.</p>
    /// <p>To flag words without changing them, choose <code>tag</code>.</p>
    pub fn set_vocabulary_filter_method(mut self, input: ::std::option::Option<crate::types::VocabularyFilterMethod>) -> Self {
        self.vocabulary_filter_method = input;
        self
    }
    /// <p>Specify how you want your custom vocabulary filter applied to your transcript.</p>
    /// <p>To replace words with <code>***</code>, choose <code>mask</code>.</p>
    /// <p>To delete words, choose <code>remove</code>.</p>
    /// <p>To flag words without changing them, choose <code>tag</code>.</p>
    pub fn get_vocabulary_filter_method(&self) -> &::std::option::Option<crate::types::VocabularyFilterMethod> {
        &self.vocabulary_filter_method
    }
    /// <p>Specify settings for the clinical note generation.</p>
    pub fn clinical_note_generation_settings(mut self, input: crate::types::ClinicalNoteGenerationSettings) -> Self {
        self.clinical_note_generation_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify settings for the clinical note generation.</p>
    pub fn set_clinical_note_generation_settings(mut self, input: ::std::option::Option<crate::types::ClinicalNoteGenerationSettings>) -> Self {
        self.clinical_note_generation_settings = input;
        self
    }
    /// <p>Specify settings for the clinical note generation.</p>
    pub fn get_clinical_note_generation_settings(&self) -> &::std::option::Option<crate::types::ClinicalNoteGenerationSettings> {
        &self.clinical_note_generation_settings
    }
    /// Consumes the builder and constructs a [`MedicalScribeSettings`](crate::types::MedicalScribeSettings).
    pub fn build(self) -> crate::types::MedicalScribeSettings {
        crate::types::MedicalScribeSettings {
            show_speaker_labels: self.show_speaker_labels,
            max_speaker_labels: self.max_speaker_labels,
            channel_identification: self.channel_identification,
            vocabulary_name: self.vocabulary_name,
            vocabulary_filter_name: self.vocabulary_filter_name,
            vocabulary_filter_method: self.vocabulary_filter_method,
            clinical_note_generation_settings: self.clinical_note_generation_settings,
        }
    }
}
