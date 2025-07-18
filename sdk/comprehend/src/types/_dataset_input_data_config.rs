// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the format and location of the input data for the dataset.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DatasetInputDataConfig {
    /// <p>A list of augmented manifest files that provide training data for your custom model. An augmented manifest file is a labeled dataset that is produced by Amazon SageMaker Ground Truth.</p>
    pub augmented_manifests: ::std::option::Option<::std::vec::Vec<crate::types::DatasetAugmentedManifestsListItem>>,
    /// <p><code>COMPREHEND_CSV</code>: The data format is a two-column CSV file, where the first column contains labels and the second column contains documents.</p>
    /// <p><code>AUGMENTED_MANIFEST</code>: The data format</p>
    pub data_format: ::std::option::Option<crate::types::DatasetDataFormat>,
    /// <p>The input properties for training a document classifier model.</p>
    /// <p>For more information on how the input file is formatted, see <a href="https://docs.aws.amazon.com/comprehend/latest/dg/prep-classifier-data.html">Preparing training data</a> in the Comprehend Developer Guide.</p>
    pub document_classifier_input_data_config: ::std::option::Option<crate::types::DatasetDocumentClassifierInputDataConfig>,
    /// <p>The input properties for training an entity recognizer model.</p>
    pub entity_recognizer_input_data_config: ::std::option::Option<crate::types::DatasetEntityRecognizerInputDataConfig>,
}
impl DatasetInputDataConfig {
    /// <p>A list of augmented manifest files that provide training data for your custom model. An augmented manifest file is a labeled dataset that is produced by Amazon SageMaker Ground Truth.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.augmented_manifests.is_none()`.
    pub fn augmented_manifests(&self) -> &[crate::types::DatasetAugmentedManifestsListItem] {
        self.augmented_manifests.as_deref().unwrap_or_default()
    }
    /// <p><code>COMPREHEND_CSV</code>: The data format is a two-column CSV file, where the first column contains labels and the second column contains documents.</p>
    /// <p><code>AUGMENTED_MANIFEST</code>: The data format</p>
    pub fn data_format(&self) -> ::std::option::Option<&crate::types::DatasetDataFormat> {
        self.data_format.as_ref()
    }
    /// <p>The input properties for training a document classifier model.</p>
    /// <p>For more information on how the input file is formatted, see <a href="https://docs.aws.amazon.com/comprehend/latest/dg/prep-classifier-data.html">Preparing training data</a> in the Comprehend Developer Guide.</p>
    pub fn document_classifier_input_data_config(&self) -> ::std::option::Option<&crate::types::DatasetDocumentClassifierInputDataConfig> {
        self.document_classifier_input_data_config.as_ref()
    }
    /// <p>The input properties for training an entity recognizer model.</p>
    pub fn entity_recognizer_input_data_config(&self) -> ::std::option::Option<&crate::types::DatasetEntityRecognizerInputDataConfig> {
        self.entity_recognizer_input_data_config.as_ref()
    }
}
impl DatasetInputDataConfig {
    /// Creates a new builder-style object to manufacture [`DatasetInputDataConfig`](crate::types::DatasetInputDataConfig).
    pub fn builder() -> crate::types::builders::DatasetInputDataConfigBuilder {
        crate::types::builders::DatasetInputDataConfigBuilder::default()
    }
}

/// A builder for [`DatasetInputDataConfig`](crate::types::DatasetInputDataConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DatasetInputDataConfigBuilder {
    pub(crate) augmented_manifests: ::std::option::Option<::std::vec::Vec<crate::types::DatasetAugmentedManifestsListItem>>,
    pub(crate) data_format: ::std::option::Option<crate::types::DatasetDataFormat>,
    pub(crate) document_classifier_input_data_config: ::std::option::Option<crate::types::DatasetDocumentClassifierInputDataConfig>,
    pub(crate) entity_recognizer_input_data_config: ::std::option::Option<crate::types::DatasetEntityRecognizerInputDataConfig>,
}
impl DatasetInputDataConfigBuilder {
    /// Appends an item to `augmented_manifests`.
    ///
    /// To override the contents of this collection use [`set_augmented_manifests`](Self::set_augmented_manifests).
    ///
    /// <p>A list of augmented manifest files that provide training data for your custom model. An augmented manifest file is a labeled dataset that is produced by Amazon SageMaker Ground Truth.</p>
    pub fn augmented_manifests(mut self, input: crate::types::DatasetAugmentedManifestsListItem) -> Self {
        let mut v = self.augmented_manifests.unwrap_or_default();
        v.push(input);
        self.augmented_manifests = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of augmented manifest files that provide training data for your custom model. An augmented manifest file is a labeled dataset that is produced by Amazon SageMaker Ground Truth.</p>
    pub fn set_augmented_manifests(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DatasetAugmentedManifestsListItem>>) -> Self {
        self.augmented_manifests = input;
        self
    }
    /// <p>A list of augmented manifest files that provide training data for your custom model. An augmented manifest file is a labeled dataset that is produced by Amazon SageMaker Ground Truth.</p>
    pub fn get_augmented_manifests(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DatasetAugmentedManifestsListItem>> {
        &self.augmented_manifests
    }
    /// <p><code>COMPREHEND_CSV</code>: The data format is a two-column CSV file, where the first column contains labels and the second column contains documents.</p>
    /// <p><code>AUGMENTED_MANIFEST</code>: The data format</p>
    pub fn data_format(mut self, input: crate::types::DatasetDataFormat) -> Self {
        self.data_format = ::std::option::Option::Some(input);
        self
    }
    /// <p><code>COMPREHEND_CSV</code>: The data format is a two-column CSV file, where the first column contains labels and the second column contains documents.</p>
    /// <p><code>AUGMENTED_MANIFEST</code>: The data format</p>
    pub fn set_data_format(mut self, input: ::std::option::Option<crate::types::DatasetDataFormat>) -> Self {
        self.data_format = input;
        self
    }
    /// <p><code>COMPREHEND_CSV</code>: The data format is a two-column CSV file, where the first column contains labels and the second column contains documents.</p>
    /// <p><code>AUGMENTED_MANIFEST</code>: The data format</p>
    pub fn get_data_format(&self) -> &::std::option::Option<crate::types::DatasetDataFormat> {
        &self.data_format
    }
    /// <p>The input properties for training a document classifier model.</p>
    /// <p>For more information on how the input file is formatted, see <a href="https://docs.aws.amazon.com/comprehend/latest/dg/prep-classifier-data.html">Preparing training data</a> in the Comprehend Developer Guide.</p>
    pub fn document_classifier_input_data_config(mut self, input: crate::types::DatasetDocumentClassifierInputDataConfig) -> Self {
        self.document_classifier_input_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The input properties for training a document classifier model.</p>
    /// <p>For more information on how the input file is formatted, see <a href="https://docs.aws.amazon.com/comprehend/latest/dg/prep-classifier-data.html">Preparing training data</a> in the Comprehend Developer Guide.</p>
    pub fn set_document_classifier_input_data_config(
        mut self,
        input: ::std::option::Option<crate::types::DatasetDocumentClassifierInputDataConfig>,
    ) -> Self {
        self.document_classifier_input_data_config = input;
        self
    }
    /// <p>The input properties for training a document classifier model.</p>
    /// <p>For more information on how the input file is formatted, see <a href="https://docs.aws.amazon.com/comprehend/latest/dg/prep-classifier-data.html">Preparing training data</a> in the Comprehend Developer Guide.</p>
    pub fn get_document_classifier_input_data_config(&self) -> &::std::option::Option<crate::types::DatasetDocumentClassifierInputDataConfig> {
        &self.document_classifier_input_data_config
    }
    /// <p>The input properties for training an entity recognizer model.</p>
    pub fn entity_recognizer_input_data_config(mut self, input: crate::types::DatasetEntityRecognizerInputDataConfig) -> Self {
        self.entity_recognizer_input_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The input properties for training an entity recognizer model.</p>
    pub fn set_entity_recognizer_input_data_config(
        mut self,
        input: ::std::option::Option<crate::types::DatasetEntityRecognizerInputDataConfig>,
    ) -> Self {
        self.entity_recognizer_input_data_config = input;
        self
    }
    /// <p>The input properties for training an entity recognizer model.</p>
    pub fn get_entity_recognizer_input_data_config(&self) -> &::std::option::Option<crate::types::DatasetEntityRecognizerInputDataConfig> {
        &self.entity_recognizer_input_data_config
    }
    /// Consumes the builder and constructs a [`DatasetInputDataConfig`](crate::types::DatasetInputDataConfig).
    pub fn build(self) -> crate::types::DatasetInputDataConfig {
        crate::types::DatasetInputDataConfig {
            augmented_manifests: self.augmented_manifests,
            data_format: self.data_format,
            document_classifier_input_data_config: self.document_classifier_input_data_config,
            entity_recognizer_input_data_config: self.entity_recognizer_input_data_config,
        }
    }
}
