import React, { useState } from 'react';
import {
    Card,
    Form,
    Button,
    Alert,
    Spinner,
    Tab,
    Tabs
} from 'react-bootstrap';
import { useDropzone } from 'react-dropzone';
import EmailAnalysisResults from './EmailAnalysisResults';

const EmailAnalysis = () => {
    const [activeTab, setActiveTab] = useState('paste');
    const [emailHeaders, setEmailHeaders] = useState('');
    const [file, setFile] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const [results, setResults] = useState(null);

    const { getRootProps, getInputProps, isDragActive } = useDropzone({
        accept: {
            'text/plain': ['.txt', '.eml'],
            'message/rfc822': ['.eml']
        },
        multiple: false,
        onDrop: acceptedFiles => {
            if (acceptedFiles.length > 0) {
                setFile(acceptedFiles[0]);
                setActiveTab('file');
            }
        }
    });

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsLoading(true);

        try {
            let response;
            if (activeTab === 'paste') {
                response = await fetch('/api/email-scan/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ headers: emailHeaders })
                });
            } else {
                const formData = new FormData();
                formData.append('file', file);
                response = await fetch('/api/email-scan/analyze-file', {
                    method: 'POST',
                    body: formData
                });
            }

            if (!response.ok) {
                throw new Error('Failed to analyze email');
            }

            const data = await response.json();
            setResults(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    const renderForm = () => (
        <Card className="mb-4">
            <Card.Header>
                <h5 className="card-title mb-0">Email Analysis</h5>
            </Card.Header>
            <Card.Body>
                <Tabs
                    activeKey={activeTab}
                    onSelect={(k) => setActiveTab(k)}
                    className="mb-3"
                >
                    <Tab eventKey="paste" title="Paste Headers">
                        <Form onSubmit={handleSubmit}>
                            <Form.Group className="mb-3">
                                <Form.Label>Email Headers</Form.Label>
                                <Form.Control
                                    as="textarea"
                                    rows={10}
                                    value={emailHeaders}
                                    onChange={(e) => setEmailHeaders(e.target.value)}
                                    placeholder="Paste email headers here..."
                                    required={activeTab === 'paste'}
                                />
                            </Form.Group>
                            <Button 
                                type="submit" 
                                disabled={isLoading || !emailHeaders.trim()}
                            >
                                {isLoading ? (
                                    <>
                                        <Spinner
                                            as="span"
                                            animation="border"
                                            size="sm"
                                            role="status"
                                            aria-hidden="true"
                                            className="me-2"
                                        />
                                        Analyzing...
                                    </>
                                ) : (
                                    'Analyze'
                                )}
                            </Button>
                        </Form>
                    </Tab>
                    <Tab eventKey="file" title="Upload File">
                        <Form onSubmit={handleSubmit}>
                            <div
                                {...getRootProps()}
                                className={`dropzone p-5 mb-3 text-center border rounded ${
                                    isDragActive ? 'border-primary' : ''
                                }`}
                            >
                                <input {...getInputProps()} />
                                {file ? (
                                    <div>
                                        <p className="mb-0">Selected file: {file.name}</p>
                                        <small>Click or drag to replace</small>
                                    </div>
                                ) : isDragActive ? (
                                    <p className="mb-0">Drop the file here...</p>
                                ) : (
                                    <div>
                                        <p className="mb-0">
                                            Drag and drop an email file here, or click to select
                                        </p>
                                        <small>Supported formats: .txt, .eml</small>
                                    </div>
                                )}
                            </div>
                            <Button 
                                type="submit" 
                                disabled={isLoading || !file}
                            >
                                {isLoading ? (
                                    <>
                                        <Spinner
                                            as="span"
                                            animation="border"
                                            size="sm"
                                            role="status"
                                            aria-hidden="true"
                                            className="me-2"
                                        />
                                        Analyzing...
                                    </>
                                ) : (
                                    'Analyze'
                                )}
                            </Button>
                        </Form>
                    </Tab>
                </Tabs>
            </Card.Body>
        </Card>
    );

    return (
        <div className="email-analysis">
            {error && (
                <Alert variant="danger" className="mb-4">
                    {error}
                </Alert>
            )}
            {renderForm()}
            {results && <EmailAnalysisResults results={results} />}
        </div>
    );
};

export default EmailAnalysis;
