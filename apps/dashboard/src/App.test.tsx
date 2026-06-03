import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { App } from './App';

describe('Pounce Sentinel dashboard', () => {
  it('renders the operational security console', () => {
    render(<App />);

    expect(screen.getByText('Pounce Sentinel')).toBeInTheDocument();
    expect(screen.getByText('Foundry tool live')).toBeInTheDocument();
    expect(screen.getAllByText('event-stream@3.3.7')).toHaveLength(2);
    expect(screen.getByText('Approve exception')).toBeInTheDocument();
  });
});
