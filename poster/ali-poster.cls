\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{ali-poster}
\LoadClass{article}

% -------------
% -- SPACING --
% -------------

\def\marginwidth{2cm}
\def\footerheight{.15\paperheight}
\def\centerwidth{.5\paperwidth}

\RequirePackage{calc}
\def\sidebarwidth{\dimexpr
	(\paperwidth-\centerwidth-\marginwidth-\marginwidth)/2-\marginwidth\relax
}

\RequirePackage[
	left=\marginwidth,
	right=\marginwidth,
	top = \marginwidth,
	bottom = 0cm,
	a1paper,
	landscape
]{geometry}

% -----------
% -- FONTS --
% -----------

\usepackage[
	fontsize=24pt,
]{fontsize}
\renewcommand{\familydefault}{\sfdefault}
\RequirePackage{parskip}

% ------------
% -- COLORS --
% ------------

\RequirePackage[dvipsnames]{xcolor}
\colorlet{highlightcolor}{BrickRed}
\colorlet{footercolor}{MidnightBlue}
\colorlet{sidebarcolor}{MidnightBlue!20!white}

% -----------
% -- TITLE -- 
% -----------

\makeatletter
\def\@maketitle{
	\textcolor{BrickRed}{\Hugerr \bf \@title}
	\bigskip

	\@author
}
\makeatother

% --------------
% -- ABSTRACT --
% --------------

% TODO

% ------------
% -- FOOTER --
% ------------

% args: width, background color
% \newsavebox\panelbox%
% \newenvironment{panel}[2]
% {%
% 	\begin{lrbox}{\panelbox}
% 		\begin{minipage}[t]{#1}
% 			}{
% 		\end{minipage}%
% 	\end{lrbox}
% 	\colorbox{#2}{%
% 		\usebox{\panelbox}
% 	}
% }

\newenvironment{panel}[2]
{%
	\begin{minipage}[t]{#1}
		}{
	\end{minipage}%
}

\newcommand{\footer}[1]{
	\vspace*{\fill}
	% \noindent\begin{minipage}[c][\footerheight][c]{\linewidth}
	\noindent\makebox[\linewidth][c]{%
		\colorbox{footercolor}{%
			\hspace{\marginwidth}
			\begin{minipage}[t][\footerheight][t]{\textwidth}
				\textcolor{white}{#1}
			\end{minipage}
			\hspace{\marginwidth}
		}
		% \end{minipage}%
	}%
}