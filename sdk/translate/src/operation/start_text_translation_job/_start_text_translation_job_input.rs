// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartTextTranslationJobInput {
    /// <p>The name of the batch translation job to be performed.</p>
    pub job_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the format and location of the input documents for the translation job.</p>
    pub input_data_config: ::std::option::Option<crate::types::InputDataConfig>,
    /// <p>Specifies the S3 folder to which your job output will be saved.</p>
    pub output_data_config: ::std::option::Option<crate::types::OutputDataConfig>,
    /// <p>The Amazon Resource Name (ARN) of an AWS Identity Access and Management (IAM) role that grants Amazon Translate read access to your input data. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/identity-and-access-management.html">Identity and access management </a>.</p>
    pub data_access_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The language code of the input language. Specify the language if all input documents share the same language. If you don't know the language of the source files, or your input documents contains different source languages, select <code>auto</code>. Amazon Translate auto detects the source language for each input document. For a list of supported language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    pub source_language_code: ::std::option::Option<::std::string::String>,
    /// <p>The target languages of the translation job. Enter up to 10 language codes. Each input file is translated into each target language.</p>
    /// <p>Each language code is 2 or 5 characters long. For a list of language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    pub target_language_codes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of a custom terminology resource to add to the translation job. This resource lists examples source terms and the desired translation for each term.</p>
    /// <p>This parameter accepts only one custom terminology resource.</p>
    /// <p>If you specify multiple target languages for the job, translate uses the designated terminology for each requested target language that has an entry for the source term in the terminology file.</p>
    /// <p>For a list of available custom terminology resources, use the <code>ListTerminologies</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/how-custom-terminology.html">Custom terminology</a>.</p>
    pub terminology_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of a parallel data resource to add to the translation job. This resource consists of examples that show how you want segments of text to be translated. If you specify multiple target languages for the job, the parallel data file must include translations for all the target languages.</p>
    /// <p>When you add parallel data to a translation job, you create an <i>Active Custom Translation</i> job.</p>
    /// <p>This parameter accepts only one parallel data resource.</p><note>
    /// <p>Active Custom Translation jobs are priced at a higher rate than other jobs that don't use parallel data. For more information, see <a href="http://aws.amazon.com/translate/pricing/">Amazon Translate pricing</a>.</p>
    /// </note>
    /// <p>For a list of available parallel data resources, use the <code>ListParallelData</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/customizing-translations-parallel-data.html"> Customizing your translations with parallel data</a>.</p>
    pub parallel_data_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A unique identifier for the request. This token is generated for you when using the Amazon Translate SDK.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Settings to configure your translation output. You can configure the following options:</p>
    /// <ul>
    /// <li>
    /// <p>Brevity: not supported.</p></li>
    /// <li>
    /// <p>Formality: sets the formality level of the output text.</p></li>
    /// <li>
    /// <p>Profanity: masks profane words and phrases in your translation output.</p></li>
    /// </ul>
    pub settings: ::std::option::Option<crate::types::TranslationSettings>,
}
impl StartTextTranslationJobInput {
    /// <p>The name of the batch translation job to be performed.</p>
    pub fn job_name(&self) -> ::std::option::Option<&str> {
        self.job_name.as_deref()
    }
    /// <p>Specifies the format and location of the input documents for the translation job.</p>
    pub fn input_data_config(&self) -> ::std::option::Option<&crate::types::InputDataConfig> {
        self.input_data_config.as_ref()
    }
    /// <p>Specifies the S3 folder to which your job output will be saved.</p>
    pub fn output_data_config(&self) -> ::std::option::Option<&crate::types::OutputDataConfig> {
        self.output_data_config.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of an AWS Identity Access and Management (IAM) role that grants Amazon Translate read access to your input data. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/identity-and-access-management.html">Identity and access management </a>.</p>
    pub fn data_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.data_access_role_arn.as_deref()
    }
    /// <p>The language code of the input language. Specify the language if all input documents share the same language. If you don't know the language of the source files, or your input documents contains different source languages, select <code>auto</code>. Amazon Translate auto detects the source language for each input document. For a list of supported language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    pub fn source_language_code(&self) -> ::std::option::Option<&str> {
        self.source_language_code.as_deref()
    }
    /// <p>The target languages of the translation job. Enter up to 10 language codes. Each input file is translated into each target language.</p>
    /// <p>Each language code is 2 or 5 characters long. For a list of language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.target_language_codes.is_none()`.
    pub fn target_language_codes(&self) -> &[::std::string::String] {
        self.target_language_codes.as_deref().unwrap_or_default()
    }
    /// <p>The name of a custom terminology resource to add to the translation job. This resource lists examples source terms and the desired translation for each term.</p>
    /// <p>This parameter accepts only one custom terminology resource.</p>
    /// <p>If you specify multiple target languages for the job, translate uses the designated terminology for each requested target language that has an entry for the source term in the terminology file.</p>
    /// <p>For a list of available custom terminology resources, use the <code>ListTerminologies</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/how-custom-terminology.html">Custom terminology</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.terminology_names.is_none()`.
    pub fn terminology_names(&self) -> &[::std::string::String] {
        self.terminology_names.as_deref().unwrap_or_default()
    }
    /// <p>The name of a parallel data resource to add to the translation job. This resource consists of examples that show how you want segments of text to be translated. If you specify multiple target languages for the job, the parallel data file must include translations for all the target languages.</p>
    /// <p>When you add parallel data to a translation job, you create an <i>Active Custom Translation</i> job.</p>
    /// <p>This parameter accepts only one parallel data resource.</p><note>
    /// <p>Active Custom Translation jobs are priced at a higher rate than other jobs that don't use parallel data. For more information, see <a href="http://aws.amazon.com/translate/pricing/">Amazon Translate pricing</a>.</p>
    /// </note>
    /// <p>For a list of available parallel data resources, use the <code>ListParallelData</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/customizing-translations-parallel-data.html"> Customizing your translations with parallel data</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parallel_data_names.is_none()`.
    pub fn parallel_data_names(&self) -> &[::std::string::String] {
        self.parallel_data_names.as_deref().unwrap_or_default()
    }
    /// <p>A unique identifier for the request. This token is generated for you when using the Amazon Translate SDK.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Settings to configure your translation output. You can configure the following options:</p>
    /// <ul>
    /// <li>
    /// <p>Brevity: not supported.</p></li>
    /// <li>
    /// <p>Formality: sets the formality level of the output text.</p></li>
    /// <li>
    /// <p>Profanity: masks profane words and phrases in your translation output.</p></li>
    /// </ul>
    pub fn settings(&self) -> ::std::option::Option<&crate::types::TranslationSettings> {
        self.settings.as_ref()
    }
}
impl StartTextTranslationJobInput {
    /// Creates a new builder-style object to manufacture [`StartTextTranslationJobInput`](crate::operation::start_text_translation_job::StartTextTranslationJobInput).
    pub fn builder() -> crate::operation::start_text_translation_job::builders::StartTextTranslationJobInputBuilder {
        crate::operation::start_text_translation_job::builders::StartTextTranslationJobInputBuilder::default()
    }
}

/// A builder for [`StartTextTranslationJobInput`](crate::operation::start_text_translation_job::StartTextTranslationJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartTextTranslationJobInputBuilder {
    pub(crate) job_name: ::std::option::Option<::std::string::String>,
    pub(crate) input_data_config: ::std::option::Option<crate::types::InputDataConfig>,
    pub(crate) output_data_config: ::std::option::Option<crate::types::OutputDataConfig>,
    pub(crate) data_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_language_code: ::std::option::Option<::std::string::String>,
    pub(crate) target_language_codes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) terminology_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) parallel_data_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) settings: ::std::option::Option<crate::types::TranslationSettings>,
}
impl StartTextTranslationJobInputBuilder {
    /// <p>The name of the batch translation job to be performed.</p>
    pub fn job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the batch translation job to be performed.</p>
    pub fn set_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name = input;
        self
    }
    /// <p>The name of the batch translation job to be performed.</p>
    pub fn get_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name
    }
    /// <p>Specifies the format and location of the input documents for the translation job.</p>
    /// This field is required.
    pub fn input_data_config(mut self, input: crate::types::InputDataConfig) -> Self {
        self.input_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the format and location of the input documents for the translation job.</p>
    pub fn set_input_data_config(mut self, input: ::std::option::Option<crate::types::InputDataConfig>) -> Self {
        self.input_data_config = input;
        self
    }
    /// <p>Specifies the format and location of the input documents for the translation job.</p>
    pub fn get_input_data_config(&self) -> &::std::option::Option<crate::types::InputDataConfig> {
        &self.input_data_config
    }
    /// <p>Specifies the S3 folder to which your job output will be saved.</p>
    /// This field is required.
    pub fn output_data_config(mut self, input: crate::types::OutputDataConfig) -> Self {
        self.output_data_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the S3 folder to which your job output will be saved.</p>
    pub fn set_output_data_config(mut self, input: ::std::option::Option<crate::types::OutputDataConfig>) -> Self {
        self.output_data_config = input;
        self
    }
    /// <p>Specifies the S3 folder to which your job output will be saved.</p>
    pub fn get_output_data_config(&self) -> &::std::option::Option<crate::types::OutputDataConfig> {
        &self.output_data_config
    }
    /// <p>The Amazon Resource Name (ARN) of an AWS Identity Access and Management (IAM) role that grants Amazon Translate read access to your input data. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/identity-and-access-management.html">Identity and access management </a>.</p>
    /// This field is required.
    pub fn data_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an AWS Identity Access and Management (IAM) role that grants Amazon Translate read access to your input data. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/identity-and-access-management.html">Identity and access management </a>.</p>
    pub fn set_data_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_access_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an AWS Identity Access and Management (IAM) role that grants Amazon Translate read access to your input data. For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/identity-and-access-management.html">Identity and access management </a>.</p>
    pub fn get_data_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_access_role_arn
    }
    /// <p>The language code of the input language. Specify the language if all input documents share the same language. If you don't know the language of the source files, or your input documents contains different source languages, select <code>auto</code>. Amazon Translate auto detects the source language for each input document. For a list of supported language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    /// This field is required.
    pub fn source_language_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_language_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language code of the input language. Specify the language if all input documents share the same language. If you don't know the language of the source files, or your input documents contains different source languages, select <code>auto</code>. Amazon Translate auto detects the source language for each input document. For a list of supported language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    pub fn set_source_language_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_language_code = input;
        self
    }
    /// <p>The language code of the input language. Specify the language if all input documents share the same language. If you don't know the language of the source files, or your input documents contains different source languages, select <code>auto</code>. Amazon Translate auto detects the source language for each input document. For a list of supported language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    pub fn get_source_language_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_language_code
    }
    /// Appends an item to `target_language_codes`.
    ///
    /// To override the contents of this collection use [`set_target_language_codes`](Self::set_target_language_codes).
    ///
    /// <p>The target languages of the translation job. Enter up to 10 language codes. Each input file is translated into each target language.</p>
    /// <p>Each language code is 2 or 5 characters long. For a list of language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    pub fn target_language_codes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.target_language_codes.unwrap_or_default();
        v.push(input.into());
        self.target_language_codes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The target languages of the translation job. Enter up to 10 language codes. Each input file is translated into each target language.</p>
    /// <p>Each language code is 2 or 5 characters long. For a list of language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    pub fn set_target_language_codes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.target_language_codes = input;
        self
    }
    /// <p>The target languages of the translation job. Enter up to 10 language codes. Each input file is translated into each target language.</p>
    /// <p>Each language code is 2 or 5 characters long. For a list of language codes, see <a href="https://docs.aws.amazon.com/translate/latest/dg/what-is-languages.html">Supported languages</a>.</p>
    pub fn get_target_language_codes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.target_language_codes
    }
    /// Appends an item to `terminology_names`.
    ///
    /// To override the contents of this collection use [`set_terminology_names`](Self::set_terminology_names).
    ///
    /// <p>The name of a custom terminology resource to add to the translation job. This resource lists examples source terms and the desired translation for each term.</p>
    /// <p>This parameter accepts only one custom terminology resource.</p>
    /// <p>If you specify multiple target languages for the job, translate uses the designated terminology for each requested target language that has an entry for the source term in the terminology file.</p>
    /// <p>For a list of available custom terminology resources, use the <code>ListTerminologies</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/how-custom-terminology.html">Custom terminology</a>.</p>
    pub fn terminology_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.terminology_names.unwrap_or_default();
        v.push(input.into());
        self.terminology_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The name of a custom terminology resource to add to the translation job. This resource lists examples source terms and the desired translation for each term.</p>
    /// <p>This parameter accepts only one custom terminology resource.</p>
    /// <p>If you specify multiple target languages for the job, translate uses the designated terminology for each requested target language that has an entry for the source term in the terminology file.</p>
    /// <p>For a list of available custom terminology resources, use the <code>ListTerminologies</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/how-custom-terminology.html">Custom terminology</a>.</p>
    pub fn set_terminology_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.terminology_names = input;
        self
    }
    /// <p>The name of a custom terminology resource to add to the translation job. This resource lists examples source terms and the desired translation for each term.</p>
    /// <p>This parameter accepts only one custom terminology resource.</p>
    /// <p>If you specify multiple target languages for the job, translate uses the designated terminology for each requested target language that has an entry for the source term in the terminology file.</p>
    /// <p>For a list of available custom terminology resources, use the <code>ListTerminologies</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/how-custom-terminology.html">Custom terminology</a>.</p>
    pub fn get_terminology_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.terminology_names
    }
    /// Appends an item to `parallel_data_names`.
    ///
    /// To override the contents of this collection use [`set_parallel_data_names`](Self::set_parallel_data_names).
    ///
    /// <p>The name of a parallel data resource to add to the translation job. This resource consists of examples that show how you want segments of text to be translated. If you specify multiple target languages for the job, the parallel data file must include translations for all the target languages.</p>
    /// <p>When you add parallel data to a translation job, you create an <i>Active Custom Translation</i> job.</p>
    /// <p>This parameter accepts only one parallel data resource.</p><note>
    /// <p>Active Custom Translation jobs are priced at a higher rate than other jobs that don't use parallel data. For more information, see <a href="http://aws.amazon.com/translate/pricing/">Amazon Translate pricing</a>.</p>
    /// </note>
    /// <p>For a list of available parallel data resources, use the <code>ListParallelData</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/customizing-translations-parallel-data.html"> Customizing your translations with parallel data</a>.</p>
    pub fn parallel_data_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.parallel_data_names.unwrap_or_default();
        v.push(input.into());
        self.parallel_data_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The name of a parallel data resource to add to the translation job. This resource consists of examples that show how you want segments of text to be translated. If you specify multiple target languages for the job, the parallel data file must include translations for all the target languages.</p>
    /// <p>When you add parallel data to a translation job, you create an <i>Active Custom Translation</i> job.</p>
    /// <p>This parameter accepts only one parallel data resource.</p><note>
    /// <p>Active Custom Translation jobs are priced at a higher rate than other jobs that don't use parallel data. For more information, see <a href="http://aws.amazon.com/translate/pricing/">Amazon Translate pricing</a>.</p>
    /// </note>
    /// <p>For a list of available parallel data resources, use the <code>ListParallelData</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/customizing-translations-parallel-data.html"> Customizing your translations with parallel data</a>.</p>
    pub fn set_parallel_data_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.parallel_data_names = input;
        self
    }
    /// <p>The name of a parallel data resource to add to the translation job. This resource consists of examples that show how you want segments of text to be translated. If you specify multiple target languages for the job, the parallel data file must include translations for all the target languages.</p>
    /// <p>When you add parallel data to a translation job, you create an <i>Active Custom Translation</i> job.</p>
    /// <p>This parameter accepts only one parallel data resource.</p><note>
    /// <p>Active Custom Translation jobs are priced at a higher rate than other jobs that don't use parallel data. For more information, see <a href="http://aws.amazon.com/translate/pricing/">Amazon Translate pricing</a>.</p>
    /// </note>
    /// <p>For a list of available parallel data resources, use the <code>ListParallelData</code> operation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/translate/latest/dg/customizing-translations-parallel-data.html"> Customizing your translations with parallel data</a>.</p>
    pub fn get_parallel_data_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.parallel_data_names
    }
    /// <p>A unique identifier for the request. This token is generated for you when using the Amazon Translate SDK.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the request. This token is generated for you when using the Amazon Translate SDK.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique identifier for the request. This token is generated for you when using the Amazon Translate SDK.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Settings to configure your translation output. You can configure the following options:</p>
    /// <ul>
    /// <li>
    /// <p>Brevity: not supported.</p></li>
    /// <li>
    /// <p>Formality: sets the formality level of the output text.</p></li>
    /// <li>
    /// <p>Profanity: masks profane words and phrases in your translation output.</p></li>
    /// </ul>
    pub fn settings(mut self, input: crate::types::TranslationSettings) -> Self {
        self.settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings to configure your translation output. You can configure the following options:</p>
    /// <ul>
    /// <li>
    /// <p>Brevity: not supported.</p></li>
    /// <li>
    /// <p>Formality: sets the formality level of the output text.</p></li>
    /// <li>
    /// <p>Profanity: masks profane words and phrases in your translation output.</p></li>
    /// </ul>
    pub fn set_settings(mut self, input: ::std::option::Option<crate::types::TranslationSettings>) -> Self {
        self.settings = input;
        self
    }
    /// <p>Settings to configure your translation output. You can configure the following options:</p>
    /// <ul>
    /// <li>
    /// <p>Brevity: not supported.</p></li>
    /// <li>
    /// <p>Formality: sets the formality level of the output text.</p></li>
    /// <li>
    /// <p>Profanity: masks profane words and phrases in your translation output.</p></li>
    /// </ul>
    pub fn get_settings(&self) -> &::std::option::Option<crate::types::TranslationSettings> {
        &self.settings
    }
    /// Consumes the builder and constructs a [`StartTextTranslationJobInput`](crate::operation::start_text_translation_job::StartTextTranslationJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_text_translation_job::StartTextTranslationJobInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_text_translation_job::StartTextTranslationJobInput {
            job_name: self.job_name,
            input_data_config: self.input_data_config,
            output_data_config: self.output_data_config,
            data_access_role_arn: self.data_access_role_arn,
            source_language_code: self.source_language_code,
            target_language_codes: self.target_language_codes,
            terminology_names: self.terminology_names,
            parallel_data_names: self.parallel_data_names,
            client_token: self.client_token,
            settings: self.settings,
        })
    }
}
