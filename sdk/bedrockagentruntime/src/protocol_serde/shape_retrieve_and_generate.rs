// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(clippy::unnecessary_wraps)]
pub fn de_retrieve_and_generate_http_error(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::retrieve_and_generate::RetrieveAndGenerateOutput,
    crate::operation::retrieve_and_generate::RetrieveAndGenerateError,
> {
    #[allow(unused_mut)]
    let mut generic_builder = crate::protocol_serde::parse_http_error_metadata(_response_status, _response_headers, _response_body)
        .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
    generic_builder = ::aws_types::request_id::apply_request_id(generic_builder, _response_headers);
    let generic = generic_builder.build();
    let error_code = match generic.code() {
        Some(code) => code,
        None => return Err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled(generic)),
    };

    let _error_message = generic.message().map(|msg| msg.to_owned());
    Err(match error_code {
        "AccessDeniedException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::AccessDeniedException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::AccessDeniedExceptionBuilder::default();
                output = crate::protocol_serde::shape_access_denied_exception::de_access_denied_exception_json_err(_response_body, output)
                    .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "BadGatewayException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::BadGatewayException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::BadGatewayExceptionBuilder::default();
                output = crate::protocol_serde::shape_bad_gateway_exception::de_bad_gateway_exception_json_err(_response_body, output)
                    .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ConflictException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::ConflictException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ConflictExceptionBuilder::default();
                output = crate::protocol_serde::shape_conflict_exception::de_conflict_exception_json_err(_response_body, output)
                    .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "DependencyFailedException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::DependencyFailedException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::DependencyFailedExceptionBuilder::default();
                output = crate::protocol_serde::shape_dependency_failed_exception::de_dependency_failed_exception_json_err(_response_body, output)
                    .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "InternalServerException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::InternalServerException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::InternalServerExceptionBuilder::default();
                output = crate::protocol_serde::shape_internal_server_exception::de_internal_server_exception_json_err(_response_body, output)
                    .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ResourceNotFoundException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::ResourceNotFoundException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ResourceNotFoundExceptionBuilder::default();
                output = crate::protocol_serde::shape_resource_not_found_exception::de_resource_not_found_exception_json_err(_response_body, output)
                    .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ServiceQuotaExceededException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::ServiceQuotaExceededException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ServiceQuotaExceededExceptionBuilder::default();
                output = crate::protocol_serde::shape_service_quota_exceeded_exception::de_service_quota_exceeded_exception_json_err(
                    _response_body,
                    output,
                )
                .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ThrottlingException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::ThrottlingException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ThrottlingExceptionBuilder::default();
                output = crate::protocol_serde::shape_throttling_exception::de_throttling_exception_json_err(_response_body, output)
                    .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        "ValidationException" => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::ValidationException({
            #[allow(unused_mut)]
            let mut tmp = {
                #[allow(unused_mut)]
                let mut output = crate::types::error::builders::ValidationExceptionBuilder::default();
                output = crate::protocol_serde::shape_validation_exception::de_validation_exception_json_err(_response_body, output)
                    .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
                let output = output.meta(generic);
                output.build()
            };
            if tmp.message.is_none() {
                tmp.message = _error_message;
            }
            tmp
        }),
        _ => crate::operation::retrieve_and_generate::RetrieveAndGenerateError::generic(generic),
    })
}

#[allow(clippy::unnecessary_wraps)]
pub fn de_retrieve_and_generate_http_response(
    _response_status: u16,
    _response_headers: &::aws_smithy_runtime_api::http::Headers,
    _response_body: &[u8],
) -> std::result::Result<
    crate::operation::retrieve_and_generate::RetrieveAndGenerateOutput,
    crate::operation::retrieve_and_generate::RetrieveAndGenerateError,
> {
    Ok({
        #[allow(unused_mut)]
        let mut output = crate::operation::retrieve_and_generate::builders::RetrieveAndGenerateOutputBuilder::default();
        output = crate::protocol_serde::shape_retrieve_and_generate::de_retrieve_and_generate(_response_body, output)
            .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?;
        output._set_request_id(::aws_types::request_id::RequestId::request_id(_response_headers).map(str::to_string));
        crate::serde_util::retrieve_and_generate_output_output_correct_errors(output)
            .build()
            .map_err(crate::operation::retrieve_and_generate::RetrieveAndGenerateError::unhandled)?
    })
}

pub fn ser_retrieve_and_generate_input(
    input: &crate::operation::retrieve_and_generate::RetrieveAndGenerateInput,
) -> ::std::result::Result<::aws_smithy_types::body::SdkBody, ::aws_smithy_types::error::operation::SerializationError> {
    let mut out = String::new();
    let mut object = ::aws_smithy_json::serialize::JsonObjectWriter::new(&mut out);
    crate::protocol_serde::shape_retrieve_and_generate_input::ser_retrieve_and_generate_input_input(&mut object, input)?;
    object.finish();
    Ok(::aws_smithy_types::body::SdkBody::from(out))
}

pub(crate) fn de_retrieve_and_generate(
    value: &[u8],
    mut builder: crate::operation::retrieve_and_generate::builders::RetrieveAndGenerateOutputBuilder,
) -> ::std::result::Result<
    crate::operation::retrieve_and_generate::builders::RetrieveAndGenerateOutputBuilder,
    ::aws_smithy_json::deserialize::error::DeserializeError,
> {
    let mut tokens_owned = ::aws_smithy_json::deserialize::json_token_iter(crate::protocol_serde::or_empty_doc(value)).peekable();
    let tokens = &mut tokens_owned;
    ::aws_smithy_json::deserialize::token::expect_start_object(tokens.next())?;
    loop {
        match tokens.next().transpose()? {
            Some(::aws_smithy_json::deserialize::Token::EndObject { .. }) => break,
            Some(::aws_smithy_json::deserialize::Token::ObjectKey { key, .. }) => match key.to_unescaped()?.as_ref() {
                "citations" => {
                    builder = builder.set_citations(crate::protocol_serde::shape_citations::de_citations(tokens)?);
                }
                "guardrailAction" => {
                    builder = builder.set_guardrail_action(
                        ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                            .map(|s| s.to_unescaped().map(|u| crate::types::GuadrailAction::from(u.as_ref())))
                            .transpose()?,
                    );
                }
                "output" => {
                    builder = builder.set_output(crate::protocol_serde::shape_retrieve_and_generate_output::de_retrieve_and_generate_output(tokens)?);
                }
                "sessionId" => {
                    builder = builder.set_session_id(
                        ::aws_smithy_json::deserialize::token::expect_string_or_null(tokens.next())?
                            .map(|s| s.to_unescaped().map(|u| u.into_owned()))
                            .transpose()?,
                    );
                }
                _ => ::aws_smithy_json::deserialize::token::skip_value(tokens)?,
            },
            other => {
                return Err(::aws_smithy_json::deserialize::error::DeserializeError::custom(format!(
                    "expected object key or end object, found: {:?}",
                    other
                )))
            }
        }
    }
    if tokens.next().is_some() {
        return Err(::aws_smithy_json::deserialize::error::DeserializeError::custom(
            "found more JSON tokens after completing parsing",
        ));
    }
    Ok(builder)
}
